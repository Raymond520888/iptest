package worker

import (
	"context"
	"fmt"
	"math"
	"os/exec"
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

var pingTimeRegex = regexp.MustCompile(`(?i)(?:時間|time)[=:]\s*([\d.]+)\s*ms`)

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

				delayStr := "未開啟"
				if enablePing {
					delayStr = measurePingDelay(ctx, target.IP, 3*time.Second)
				}

				hops, err := tr.Trace(ctx, target.IP, target.Port)
				if err != nil {
					res := Result{Target: target, ISP: "測試異常", LineType: "未知", Delay: delayStr, Err: err}
					results <- res
					if onResult != nil {
						onResult(res)
					}
					continue
				}

				// 收集路徑上命中的 ASN；若命中 CMIN2 (AS58807) 可提前結束
				var hitASNs []string
				seen := make(map[string]bool)
				for _, hopAddr := range hops {
					asn := matcher.Match(hopAddr)
					if asn != "" && !seen[asn] {
						seen[asn] = true
						hitASNs = append(hitASNs, asn)
						if asn == "AS58807" {
							break
						}
					}
				}

				isp, lineType, asnStr := filter.AnalyzeRoute(hitASNs)
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
	return out
}
