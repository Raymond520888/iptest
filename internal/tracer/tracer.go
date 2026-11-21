package tracer

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

type Tracer struct {
	timeout time.Duration
	maxHops int
}

func NewTracer(timeout time.Duration, maxHops int) *Tracer {
	return &Tracer{timeout: timeout, maxHops: maxHops}
}

// Trace 执行 TCP traceroute，返回有效的跳地址列表。
// 无效跳（Success=false 或 Address=nil）会被显式过滤。
func (t *Tracer) Trace(ctx context.Context, targetIP string) ([]netip.Addr, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, nil
	}

	res, err := trace.Traceroute(trace.TCPTrace, trace.Config{
		Context:          ctx,
		BeginHop:         1,
		MaxHops:          t.maxHops,
		NumMeasurements:  1,
		MaxAttempts:      2,
		ParallelRequests: 6,
		Timeout:          2 * time.Second,
		PacketInterval:   50,
		TTLInterval:      50,
		DstIP:            ip,
		DstPort:          443,
		IPGeoSource:      ipgeo.GetSource("DISABLE-GEOIP"),
		Lang:             "en",
	})
	if err != nil && res == nil {
		return nil, err
	}

	hops := make([]netip.Addr, 0, len(res.Hops))
	for _, attempts := range res.Hops {
		for _, attempt := range attempts {
			if !attempt.Success || attempt.Address == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(attempt.Address.(*net.IPAddr).IP)
			if !ok {
				continue
			}
			hops = append(hops, addr.Unmap())
			break
		}
	}
	return hops, err
}
