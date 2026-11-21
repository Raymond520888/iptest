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
					// 延迟测试尚未接入，当前返回占位说明
					delayStr = "暂未支持"
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

				// 收集路径上命中的 ASN；若命中 CMIN2 (AS58807) 可提前结束
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
