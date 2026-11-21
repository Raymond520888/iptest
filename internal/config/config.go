package config

import "time"

type RouteRule struct {
	ISP      string
	LineType string
	ASNs     []string
}

var (
	// TargetASNs 與 nexttraceV5.py 保持一致
	TargetASNs = []string{"AS4809", "AS4812", "AS9929", "AS58807", "AS58453", "AS4134"}

	// RouteRules 基礎線路判定規則（對齊 nexttraceV5.py）
	RouteRules = []RouteRule{
		{ISP: "中国电信", LineType: "CN2 GIA/GT", ASNs: []string{"AS4809"}},
		{ISP: "中国电信", LineType: "CN2", ASNs: []string{"AS4812"}},
		{ISP: "中国电信", LineType: "163 骨干网", ASNs: []string{"AS4134"}},
		{ISP: "中国联通", LineType: "CUII（A网）", ASNs: []string{"AS9929"}},
		{ISP: "中国移动", LineType: "CMIN2", ASNs: []string{"AS58807"}},
		{ISP: "中国移动", LineType: "CMI", ASNs: []string{"AS58453"}},
	}

	RIPEstatURL = "https://stat.ripe.net/data/announced-prefixes/data.json"
	DBV4Path    = "asn_prefixes_v4.json"
	DBV6Path    = "asn_prefixes_v6.json"

	// HardcodedPrefixes 已知關鍵網段硬編碼補充表（對齊 KNOWN_IP_RANGES）
	HardcodedPrefixes = map[string][]string{
		"AS4809":  {"59.43.0.0/16"},   // 电信 CN2 骨干
		"AS4134":  {"202.97.0.0/16"},  // 电信 163 骨干
		"AS4837":  {"219.158.0.0/16"}, // 联通 169 骨干
		"AS9808":  {"221.183.0.0/16"}, // 移动骨干
		"AS9929":  {"218.105.0.0/16"}, // 联通 CUII 部分网段
		"AS58807": {"223.120.0.0/16"}, // 移动 CMIN2 部分网段
	}
)

type Config struct {
	InputFile   string
	Concurrency int
	Timeout     time.Duration
	MaxHops     int
	EnablePing  bool
}
