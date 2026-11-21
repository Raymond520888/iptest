package tracer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var verRegex = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

type ntVersion struct {
	major int
	minor int
	patch int
}

func (v ntVersion) ge(major, minor, patch int) bool {
	if v.major != major {
		return v.major > major
	}
	if v.minor != minor {
		return v.minor > minor
	}
	return v.patch >= patch
}

type Tracer struct {
	timeout time.Duration
	maxHops int
	exePath string

	once    sync.Once
	version *ntVersion
}

func NewTracer(timeout time.Duration, maxHops int) *Tracer {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxHops <= 0 {
		maxHops = 30
	}
	return &Tracer{
		timeout: timeout,
		maxHops: maxHops,
		exePath: resolveNextTraceExe(),
	}
}

func resolveNextTraceExe() string {
	exeName := "nexttrace"
	if runtime.GOOS == "windows" {
		exeName = "nexttrace.exe"
	}

	if execPath, err := os.Executable(); err == nil && execPath != "" {
		candidate := filepath.Join(filepath.Dir(execPath), exeName)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
	}

	if info, err := os.Stat(exeName); err == nil && !info.IsDir() {
		abs, absErr := filepath.Abs(exeName)
		if absErr == nil {
			return abs
		}
		return exeName
	}

	if found, err := exec.LookPath(exeName); err == nil && found != "" {
		return found
	}

	return ""
}

func parseDstPort(portStr string) int {
	if portStr == "" {
		return 443
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return 443
	}
	return p
}

func (t *Tracer) detectVersion(ctx context.Context) *ntVersion {
	t.once.Do(func() {
		if t.exePath == "" {
			return
		}
		for _, flag := range []string{"--version", "-V", "-v"} {
			vCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			cmd := exec.CommandContext(vCtx, t.exePath, flag)
			hideConsoleWindow(cmd)
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil && len(out) == 0 {
				continue
			}
			m := verRegex.FindStringSubmatch(string(out))
			if len(m) == 4 {
				maj, _ := strconv.Atoi(m[1])
				min, _ := strconv.Atoi(m[2])
				pat, _ := strconv.Atoi(m[3])
				t.version = &ntVersion{major: maj, minor: min, patch: pat}
				return
			}
		}
	})
	return t.version
}

func (t *Tracer) buildArgs(ctx context.Context, ipStr string, dstPort int) []string {
	ver := t.detectVersion(ctx)
	var args []string
	if ver != nil && ver.ge(1, 7, 0) {
		args = append(args, "--traceroute", "--raw")
	} else {
		args = append(args, "--raw")
	}
	args = append(args,
		"-d", "disable-geoip",
		"-n",
		"-C",
		"-q", "1",
		"-m", strconv.Itoa(t.maxHops),
		"-p", strconv.Itoa(dstPort),
		ipStr,
	)
	return args
}

// Trace 调用外部 nexttrace 程序，解析 `|` 分隔的原始输出并返回跳点地址列表。
func (t *Tracer) Trace(ctx context.Context, targetIP, port string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(targetIP) == "" {
		return nil, fmt.Errorf("目标地址为空")
	}
	if t.exePath == "" {
		return nil, fmt.Errorf("未找到 nexttrace 可执行文件，请将其放在程序同级目录或系统 PATH 中")
	}

	ip := net.ParseIP(strings.TrimSpace(targetIP))
	if ip == nil {
		lookupTimeout := t.timeout
		if lookupTimeout > 10*time.Second {
			lookupTimeout = 10 * time.Second
		}
		lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", strings.TrimSpace(targetIP))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("域名解析失败 (%s): %w", targetIP, err)
		}
		for _, candidate := range ips {
			if candidate != nil {
				ip = candidate
				break
			}
		}
		if ip == nil {
			return nil, fmt.Errorf("域名未返回有效 IP (%s)", targetIP)
		}
	}

	dstPort := parseDstPort(port)
	runCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	args := t.buildArgs(runCtx, ip.String(), dstPort)
	cmd := exec.Command(t.exePath, args...)
	hideConsoleWindow(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建 stdout 管道失败: %w", err)
	}
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 nexttrace 失败: %w", err)
	}

	doneWatch := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-doneWatch:
		}
	}()

	var hops []netip.Addr
	seenHop := make(map[netip.Addr]bool)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		hopNumStr := strings.TrimSpace(parts[0])
		if hopNumStr == "" || !isDigits(hopNumStr) {
			continue
		}
		hopIPStr := strings.TrimSpace(parts[1])
		if hopIPStr == "" || hopIPStr == "*" {
			continue
		}
		parsed, parseErr := netip.ParseAddr(hopIPStr)
		if parseErr != nil || !parsed.IsValid() {
			continue
		}
		addr := parsed.Unmap()
		if !seenHop[addr] {
			seenHop[addr] = true
			hops = append(hops, addr)
		}
	}
	scanErr := scanner.Err()

	waitErr := cmd.Wait()
	close(doneWatch)

	if errors.Is(ctx.Err(), context.Canceled) {
		return hops, context.Canceled
	}
	if len(hops) > 0 {
		return hops, nil
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("nexttrace 探测超时 (%v)", t.timeout)
	}
	if scanErr != nil {
		return nil, fmt.Errorf("读取 nexttrace 输出失败: %w", scanErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("nexttrace 执行异常: %w", waitErr)
	}
	return hops, nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
