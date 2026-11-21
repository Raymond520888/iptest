package filter

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ip-batch-track/internal/config"
)

var (
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}
	targetPattern = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?$`)
)

// ---------- RIPEstat 前缀拉取 ----------

type ripeStatResp struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func fetchPrefixes(asn, starttime string, ipVersion int) ([]string, error) {
	url := fmt.Sprintf("%s?resource=%s&starttime=%s", config.RIPEstatURL, asn, starttime)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat 返回异常状态码: %d", resp.StatusCode)
	}

	var data ripeStatResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var cidrs []string
	for _, item := range data.Data.Prefixes {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if (ipVersion == 4 && prefix.Addr().Is4()) || (ipVersion == 6 && prefix.Addr().Is6()) {
			cidrs = append(cidrs, prefix.String())
		}
	}
	return cidrs, nil
}

func UpdatePrefixDB() error {
	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	resultV4 := make(map[string][]string)
	resultV6 := make(map[string][]string)

	for _, asn := range config.TargetASNs {
		// IPv4
		cidrsV4, err := fetchPrefixes(asn, today, 4)
		if err != nil || len(cidrsV4) == 0 {
			fallbackV4, fbErr := fetchPrefixes(asn, yesterday, 4)
			if fbErr == nil && len(fallbackV4) > 0 {
				cidrsV4 = fallbackV4
			} else if err != nil {
				return fmt.Errorf("拉取 %s IPv4 前缀失败: %w", asn, err)
			}
		}
		resultV4[asn] = cidrsV4

		// IPv6
		cidrsV6, err := fetchPrefixes(asn, today, 6)
		if err != nil || len(cidrsV6) == 0 {
			fallbackV6, fbErr := fetchPrefixes(asn, yesterday, 6)
			if fbErr == nil && len(fallbackV6) > 0 {
				cidrsV6 = fallbackV6
			} else if err != nil {
				return fmt.Errorf("拉取 %s IPv6 前缀失败: %w", asn, err)
			}
		}
		resultV6[asn] = cidrsV6
	}

	v4data, err := json.MarshalIndent(resultV4, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 IPv4 前缀表失败: %w", err)
	}
	v6data, err := json.MarshalIndent(resultV6, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 IPv6 前缀表失败: %w", err)
	}

	if err := os.WriteFile(config.DBV4Path, v4data, 0644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", config.DBV4Path, err)
	}
	if err := os.WriteFile(config.DBV6Path, v6data, 0644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", config.DBV6Path, err)
	}
	return nil
}

// ---------- ASN 匹配器（最长前缀匹配 + 硬编码兜底） ----------

type prefixEntry struct {
	prefix netip.Prefix
	asn    string
}

type ASNMatcher struct {
	entries []prefixEntry
}

func LoadMatcher() (*ASNMatcher, error) {
	prefixMap := make(map[string][]string)
	loaded := false

	// 1. 先合并硬编码兜底
	for asn, cidrs := range config.HardcodedPrefixes {
		prefixMap[asn] = append(prefixMap[asn], cidrs...)
	}

	// 2. 合并本地 JSON 前缀表
	for _, path := range []string{config.DBV4Path, config.DBV6Path} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var m map[string][]string
		if err := json.Unmarshal(data, &m); err == nil {
			for asn, cidrs := range m {
				prefixMap[asn] = append(prefixMap[asn], cidrs...)
			}
			loaded = true
		}
	}

	if !loaded && len(prefixMap) == 0 {
		return nil, fmt.Errorf("未找到有效的前缀表文件且无硬编码数据")
	}

	matcher := &ASNMatcher{}
	seen := make(map[netip.Prefix]bool)
	for asn, cidrs := range prefixMap {
		for _, cidr := range cidrs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			p = p.Masked()
			if seen[p] {
				continue
			}
			seen[p] = true
			matcher.entries = append(matcher.entries, prefixEntry{prefix: p, asn: asn})
		}
	}
	return matcher, nil
}

func (m *ASNMatcher) Match(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}

	// 统一转换为标准地址（例如将 ::ffff:1.2.3.4 还原为 1.2.3.4）
	addr = addr.Unmap()

	// 最长前缀匹配 (LPM)：硬编码兜底网段已在 LoadMatcher 中合并，由前缀长度决定优先级
	bestBits := -1
	bestASN := ""
	for _, e := range m.entries {
		if e.prefix.Contains(addr) && e.prefix.Bits() > bestBits {
			bestBits = e.prefix.Bits()
			bestASN = e.asn
		}
	}
	return bestASN
}

// ---------- 线路分析 ----------

func AnalyzeRoute(hitASNs []string) (string, string, string) {
	asnSet := make(map[string]bool, len(hitASNs))
	for _, a := range hitASNs {
		asnSet[a] = true
	}

	asnStr := strings.Join(hitASNs, "/")
	if asnStr == "" {
		asnStr = "无"
	}

	var isps []string
	var lineTypes []string
	seenISP := make(map[string]bool)
	seenType := make(map[string]bool)

	for _, rule := range config.RouteRules {
		matched := false
		for _, kw := range rule.ASNs {
			if asnSet[kw] {
				matched = true
				break
			}
		}
		if matched {
			if !seenISP[rule.ISP] {
				seenISP[rule.ISP] = true
				isps = append(isps, rule.ISP)
			}
			if !seenType[rule.LineType] {
				seenType[rule.LineType] = true
				lineTypes = append(lineTypes, rule.LineType)
			}
		}
	}

	if len(isps) > 0 {
		return strings.Join(isps, "/"), strings.Join(lineTypes, " / "), asnStr
	}

	return "非精品线路", "普通线路/骨干网", asnStr
}

// ---------- 目标解析 ----------

func ParseTargetLine(line string) (ip, port, country string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", ""
	}

	if idx := strings.Index(line, "#"); idx != -1 {
		country = strings.TrimSpace(line[idx+1:])
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return "", "", country
	}

	// 优先尝试标准 host:port（兼容 [IPv6]:port、域名:port、IPv4:port）
	if host, p, err := net.SplitHostPort(line); err == nil {
		if portNum, pErr := strconv.Atoi(p); pErr == nil && portNum >= 1 && portNum <= 65535 {
			return strings.Trim(host, "[]"), p, country
		}
	}

	matches := targetPattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		host := strings.Trim(matches[1], "[]")
		if len(matches) >= 4 && matches[3] != "" {
			if portNum, err := strconv.Atoi(matches[3]); err == nil && portNum >= 1 && portNum <= 65535 {
				port = matches[3]
			}
		}
		return host, port, country
	}

	return strings.Trim(line, "[]"), "", country
}
