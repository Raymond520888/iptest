func (m *ASNMatcher) Match(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	ipStr := addr.String()
	// 硬编码优先，避免前缀表数据滞后
	if strings.HasPrefix(ipStr, "59.43.") {
		return "AS4809" // CN2 骨干
	}
	if strings.HasPrefix(ipStr, "202.97.") {
		return "AS4134" // 163 骨干
	}
	if strings.HasPrefix(ipStr, "69.194.") {
		return "AS23764" // CTGNet
	}
	// ... 后续最长前缀匹配逻辑不变
}
