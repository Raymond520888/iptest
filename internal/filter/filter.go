package filter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ip-batch-track/internal/config"
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
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data ripeStatResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var cidrs []string
	for _, item := range data.Data.Prefixes {
		ip, _, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			continue
		}
		if (ipVersion == 4 && ip.Is4()) || (ipVersion == 6 && ip.Is6()) {
			cidrs = append(cidrs, item.Prefix)
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
		cidrs, err := fetchPrefixes(asn, today, 4)
		if err != nil || len(cidrs) == 0 {
			cidrs, _ = fetchPrefixes(asn, yesterday, 4)
		}
		resultV4[asn] = cidrs

		// IPv6
		cidrs, err = fetchPrefixes(asn, today, 6)
		if err != nil || len(cidrs) == 0 {
			cidrs, _ = fetchPrefixes(asn, yesterday, 6)
		}
		resultV6[asn] = cidrs
	}

	v4data, _ := json.MarshalIndent(resultV4, "", "  ")
	v6data, _ := json.MarshalIndent(resultV6, "", "  ")
	os.WriteFile(config.DBV4Path, v4data, 0644)
	os.WriteFile(config.DBV6Path, v6data, 0644)
	return nil
}

// ---------- ASN 匹配器（最长前缀匹配 + 硬编码拦截） ----------

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
	
	ipStr := addr.String()

	// 硬编码优先：确保关键网段即使 API 数据滞后也能精准识别
	if strings.HasPrefix(ipStr, "59.43.") {
		return "AS4809" // 电信 CN2 核心
	}
	if strings.HasPrefix(ipStr, "202.97.") {
		return "AS4134" // 电信 163 骨干（用于判 GT）
	}
	if strings.HasPrefix(ipStr, "69.194.") {
		return "AS23764" // 电信 CTGNet
	}

	// 最长前缀匹配 (LPM)
	addr = addr.Unmap()
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

// ---------- 线路分析（重点修复 GIA/GT 判定） ----------

func AnalyzeRoute(hitASNs []string) (string, string, string) {
	asnSet := make(map[string]bool)
	for _, a := range hitASNs {
		asnSet[a] = true
	}

	asnStr := strings.Join(hitASNs, "/")
	if asnStr == "" {
		asnStr = "无"
	}

	// 1. 优先判断电信优化线路
	if asnSet["AS4809"] {
		// 如果同时包含 163 骨干 (AS4134)，说明是半程优化 GT
		if asnSet["AS4134"] {
			return "中国电信", "CN2 GT（半程优化）", asnStr
		}
		// 否则判定为全程优化 GIA
		return "中国电信", "CN2 GIA（全程优化）", asnStr
	}
	
	// 备选：CTGNet 或 CN2（AS4812）
	if asnSet["AS23764"] {
		return "中国电信", "CTGNet（国际精品）", asnStr
	}

	// 2. 遍历基础规则判断联通 / 移动
	var isps, types []string
	seenISP, seenType := map[string]bool{}, map[string]bool{}

	for _, rule := range config.RouteRules {
		for _, target := range rule.ASNs {
			if asnSet[target] {
				if !seenISP[rule.ISP] {
					isps = append(isps, rule.ISP)
					seenISP[rule.ISP] = true
				}
				if !seenType[rule.LineType] {
					types = append(types, rule.LineType)
					seenType[rule.LineType] = true
				}
			}
		}
	}

	if len(isps) > 0 {
		return strings.Join(isps, "/"), strings.Join(types, " / "), asnStr
	}

	// 3. 未命中任何精品线路
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

	re := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	match := re.FindString(line)
	if match != "" {
		ip = match
		rest := strings.Replace(line, ip, "", 1)
		if strings.HasPrefix(rest, ":") {
			p := strings.TrimSpace(rest[1:])
			if _, err := strconv.Atoi(p); err == nil {
				port = p
			}
		}
	} else {
		ip = line
	}
	return ip, port, country
}
