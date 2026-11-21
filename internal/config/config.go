var (
	HardcodedPrefixes = map[string][]string{
		"AS4809": {"59.43.0.0/16"},
		"AS4134": {"202.97.0.0/16"},   // 163 普通骨干，用于识别 GT 半程优化
		"AS23764": {"69.194.0.0/16"},  // CTGNet 国际精品
	}
)

// 电信规则：AS4809 视为 CN2，若同时出现 AS4134 则降级为 GT
var RouteRules = []RouteRule{
	{"中国电信", "CN2 GIA/GT", []string{"AS4809"}},
	{"中国电信", "CN2", []string{"AS4812"}},
	// ... 联通、移动规则保持不变
}
