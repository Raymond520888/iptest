package config

import "time"

type RouteRule struct {
	ISP      string
	LineType string
	ASNs     []string
}

var (
	TargetASNs = []string{"AS4809", "AS4812", "AS9929", "AS58807", "AS58453"}

	RouteRules = []RouteRule{
		{"中国电信", "CN2 GIA/GT", []string{"AS4809"}},
		{"中国电信", "CN2", []string{"AS4812"}},
		{"中国联通", "CUII（A网）", []string{"AS9929"}},
		{"中国移动", "CMIN2", []string{"AS58807"}},
		{"中国移动", "CMI", []string{"AS58453"}},
	}

	RIPEstatURL = "https://stat.ripe.net/data/announced-prefixes/data.json"
	DBV4Path    = "asn_prefixes_v4.json"
	DBV6Path    = "asn_prefixes_v6.json"

	// 硬编码兜底：RIPEstat 数据可能滞后，关键网段直接拦截
	HardcodedPrefixes = map[string][]string{
		"AS4809": {"59.43.0.0/16"},
		"AS4837": {"219.158.0.0/16"},
		"AS9808": {"221.183.0.0/16"},
		"AS9929": {"218.105.0.0/16"},
		"AS58807": {"223.120.0.0/16"},
	}
)

type Config struct {
	InputFile   string
	Concurrency int
	Timeout     time.Duration
	MaxHops     int
	EnablePing  bool
}
