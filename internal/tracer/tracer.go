package tracer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

type Tracer struct {
	timeout time.Duration
	maxHops int
}

func NewTracer(timeout time.Duration, maxHops int) *Tracer {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxHops <= 0 {
		maxHops = 30
	}
	return &Tracer{timeout: timeout, maxHops: maxHops}
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

// Trace 执行 TCP traceroute，返回有效的跳地址列表。
// 无效跳（Success=false 或 Address=nil）会被显式过滤。
func (t *Tracer) Trace(ctx context.Context, targetIP, port string) ([]netip.Addr, error) {
	if targetIP == "" {
		return nil, fmt.Errorf("目标地址为空")
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		// 支持域名目标：先解析为 IP 地址
		lookupCtx, cancel := context.WithTimeout(ctx, t.timeout)
		defer cancel()

		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", targetIP)
		if err != nil {
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

	res, err := trace.Traceroute(trace.TCPTrace, trace.Config{
		Context:          ctx,
		BeginHop:         1,
		MaxHops:          t.maxHops,
		NumMeasurements:  1,
		MaxAttempts:      2,
		ParallelRequests: 6,
		Timeout:          t.timeout,
		PacketInterval:   50,
		TTLInterval:      50,
		DstIP:            ip,
		DstPort:          dstPort,
		IPGeoSource:      ipgeo.GetSource("DISABLE-GEOIP"),
		Lang:             "en",
	})
	if res == nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("traceroute 未返回有效结果")
	}

	hops := make([]netip.Addr, 0, len(res.Hops))
	for _, attempts := range res.Hops {
		for _, attempt := range attempts {
			if !attempt.Success || attempt.Address == nil {
				continue
			}

			var rawIP net.IP
			switch addrVal := attempt.Address.(type) {
			case *net.IPAddr:
				rawIP = addrVal.IP
			case *net.IPNet:
				rawIP = addrVal.IP
			case *net.TCPAddr:
				rawIP = addrVal.IP
			case *net.UDPAddr:
				rawIP = addrVal.IP
			default:
				if parsed, parseErr := netip.ParseAddr(attempt.Address.String()); parseErr == nil && parsed.IsValid() {
					hops = append(hops, parsed.Unmap())
					break
				}
				continue
			}

			addr, ok := netip.AddrFromSlice(rawIP)
			if !ok || !addr.IsValid() {
				continue
			}
			hops = append(hops, addr.Unmap())
			break
		}
	}
	return hops, err
}
