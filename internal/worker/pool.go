package worker

import (
	"context"
	"sync"

	"ip-batch-track/internal/filter"
	"ip-batch-track/internal/tracer"
)

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

func Run(ctx context.Context, targets []Target, tr *tracer.Tracer, matcher *filter.ASNMatcher, concurrency int, enablePing bool) []Result {
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

				delayStr := "未开启测试"
				if enablePing {
					// 延迟测试可在此扩展，当前保持占位
					delayStr = "N/A"
				}

				hops, err := tr.Trace(ctx, target.IP)
				if err != nil {
					results <- Result{Target: target, ISP: "测试异常", LineType: "未知", Delay: delayStr, Err: err}
					continue
				}

				var hitASNs []string
				seen := make(map[string]bool)
				for _, hopAddr := range hops {
					asn := matcher.Match(hopAddr)
					if asn != "" && !seen[asn] {
						seen[asn] = true
						hitASNs = append(hitASNs, asn)
					}
				}

				isp, lineType, asnStr := filter.AnalyzeRoute(hitASNs)
				results <- Result{Target: target, ISP: isp, LineType: lineType, ASNStr: asnStr, Delay: delayStr}
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
