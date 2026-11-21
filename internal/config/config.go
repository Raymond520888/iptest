package config

import "time"

type RouteRule struct {
	ISP      string
	LineType string
	ASNs     []string
}

var (
	// TargetASNs 需要拉取的前缀表 ASN
	// 补充了 AS4134 (163骨干) 和 AS23764 (CTGNet)，用于辅助判定电信线路
	TargetASNs = []string{"AS4809", "AS4812", "AS9929", "AS58807", "AS58453", "AS4134", "AS23764"}
	
	// RouteRules 基础线路判定规则
	RouteRules = []RouteRule{
		{"中国电信", "CN2", []string{"AS4812"}},
		{"中国联通", "CUII（A网）", []string{"AS9929"}},
		{"中国移动", "CMIN2", []string{"AS58807"}},
		{"中国移动", "CMI", []string{"AS58453"}},
	}

	RIPEstatURL  = "https://stat.ripe.net/data/announced-prefixes/data.json"
	DBV4Path     = "asn_prefixes_v4.json"
	DBV6Path     = "asn_prefixes_v6.json"

	// HardcodedPrefixes 硬编码兜底：避免 RIPEstat 数据滞后导致关键节点漏判
	HardcodedPrefixes = map[string][]string{
		"AS4809":  {"59.43.0.0/16"},   // 电信 CN2 核心骨干
		"AS4134":  {"202.97.0.0/16"},  // 电信 163 普通骨干（GT 识别关键）
		"AS23764": {"69.194.0.0/16"},  // 电信 CTGNet
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
