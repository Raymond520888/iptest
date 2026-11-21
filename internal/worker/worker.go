package worker

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ip-batch-track/internal/filter"
	"ip-batch-track/internal/tracer"
)

var pingTimeRegex = regexp.MustCompile(`(?i)(?:时间|時間|time)\s*[=:]\s*[<~]?\s*([\d.]+)\s*ms`)

type Target struct {
	IP      string
	Port    string
	Country string
}

type Result struct {
	Target
	ISP      string
	LineType string
	ASNStr   string
	Delay    string
	Err      error
}

func resolveResultFilePath() string {
	const fileName = "Result.txt"
	if exePath, err := os.Executable(); err == nil && strings.TrimSpace(exePath) != "" {
		return filepath.Join(filepath.Dir(exePath), fileName)
	}
	return filepath.Join(".", fileName)
}

func measurePingDelay(ctx context.Context, ip string, timeout time.Duration) string {
	if strings.TrimSpace(ip) == "" {
		return "N/A"
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs < 500 {
			timeoutMs = 1000
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "3", "-w", strconv.Itoa(timeoutMs), ip)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	} else {
		sec := int(math.Ceil(timeout.Seconds()))
		if sec < 1 {
			sec = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "3", "-W", strconv.Itoa(sec), ip)
	}

	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "N/A"
	}
	if err != nil && len(out) == 0 {
		return "N/A"
	}

	matches := pingTimeRegex.FindAllStringSubmatch(string(out), -1)
	if len(matches) == 0 {
		return "N/A"
	}

	var sum float64
	var count int
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		val, parseErr := strconv.ParseFloat(m[1], 64)
		if parseErr != nil {
			continue
		}
		sum += val
		count++
	}
	if count == 0 {
		return "N/A"
	}

	avg := int(math.Round(sum / float64(count)))
	return fmt.Sprintf("%dms", avg)
}

func filterOutAS9808(asnStr string) string {
	if strings.TrimSpace(asnStr) == "" {
		return ""
	}
	parts := strings.Split(asnStr, "/")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || strings.EqualFold(trimmed, "AS9808") {
			continue
		}
		filtered = append(filtered, trimmed)
	}
	return strings.Join(filtered, "/")
}

func writeResultFile(filename string, results []Result) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("总计条数: %d\n", len(results)))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, r := range results {
		targetAddr := r.IP
		if r.Port != "" {
			targetAddr = fmt.Sprintf("%s:%s", r.IP, r.Port)
		}
		if r.Err != nil {
			sb.WriteString(fmt.Sprintf("%s | 异常: %v | 延迟: %s\n", targetAddr, r.Err, r.Delay))
			continue
		}
		asnDisplay := r.ASNStr
		if asnDisplay == "" {
			asnDisplay = "无"
		}
		sb.WriteString(fmt.Sprintf("%s | 运营商: %s | 线路: %s | ASN: %s | 延迟: %s\n",
			targetAddr, r.ISP, r.LineType, asnDisplay, r.Delay))
	}

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

func Run(
	ctx context.Context,
	targets []Target,
	tr *tracer.Tracer,
	matcher *filter.ASNMatcher,
	concurrency int,
	enablePing bool,
	onResult func(Result),
) []Result {
	if len(targets) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	jobs := make(chan Target)
	results := make(chan Result, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				delayStr := "未开启"
				if enablePing {
					delayStr = measurePingDelay(ctx, target.IP, 3*time.Second)
				}

				hops, err := tr.Trace(ctx, target.IP, target.Port)
				if err != nil {
					res := Result{Target: target, ISP: "测试异常", LineType: "未知", Delay: delayStr, Err: err}
					results <- res
					if onResult != nil {
						onResult(res)
					}
					continue
				}

				// 收集路径上命中的 ASN（忽略 AS9808）；若命中 CMIN2 (AS58807) 可提前结束
				var hitASNs []string
				seen := make(map[string]bool)
				for _, hopAddr := range hops {
					asn := matcher.Match(hopAddr)
					if asn != "" && asn != "AS9808" && !seen[asn] {
						seen[asn] = true
						hitASNs = append(hitASNs, asn)
						if asn == "AS58807" {
							break
						}
					}
				}

				isp, lineType, asnStr := filter.AnalyzeRoute(hitASNs)
				asnStr = filterOutAS9808(asnStr)
				res := Result{Target: target, ISP: isp, LineType: lineType, ASNStr: asnStr, Delay: delayStr}
				results <- res
				if onResult != nil {
					onResult(res)
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var out []Result
	for r := range results {
		out = append(out, r)
	}

	resultPath := resolveResultFilePath()
	_ = writeResultFile(resultPath, out)

	return out
}
