package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"ip-batch-track/internal/config"
	"ip-batch-track/internal/filter"
	"ip-batch-track/internal/tracer"
	"ip-batch-track/internal/worker"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	fmt.Println("ip批量路由测试                  Make by Raymond")

	var (
		inputFile   = flag.String("f", "testdata/ips.txt", "目标文件路径")
		conc        = flag.Int("c", 128, "并发数")
		timeout     = flag.Duration("timeout", 120*time.Second, "单次追踪超时")
		maxHops     = flag.Int("m", 30, "最大跳数")
		enablePing  = flag.Bool("ping", false, "启用延迟测试（当前为占位功能）")
		forceUpdate = flag.Bool("update", false, "强制从 RIPEstat 更新前缀表数据")
	)

	fmt.Printf("IP Batch Track %s (commit: %s)\n", version, commit)
	flag.Parse()

	cfg := config.Config{
		InputFile:   *inputFile,
		Concurrency: *conc,
		Timeout:     *timeout,
		MaxHops:     *maxHops,
		EnablePing:  *enablePing,
	}

	if *forceUpdate {
		fmt.Println("[+] 强制更新模式：正在从 RIPEstat 拉取最新前缀表...")
		if err := filter.UpdatePrefixDB(); err != nil {
			fmt.Printf("[-] 前缀表更新失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 前缀表更新完成")
	} else if _, err := os.Stat(config.DBV4Path); os.IsNotExist(err) {
		fmt.Println("[+] 未找到本地前缀表，正在从 RIPEstat 拉取更新...")
		if err := filter.UpdatePrefixDB(); err != nil {
			fmt.Printf("[-] 前缀表更新失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] 前缀表更新完成")
	}

	matcher, err := filter.LoadMatcher()
	if err != nil {
		fmt.Printf("[-] 加载前缀表失败: %v\n", err)
		os.Exit(1)
	}

	file, err := os.Open(cfg.InputFile)
	if err != nil {
		fmt.Printf("[-] 无法打开文件: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var targets []worker.Target
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip, port, country := filter.ParseTargetLine(scanner.Text())
		if ip != "" {
			targets = append(targets, worker.Target{IP: ip, Port: port, Country: country})
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] 读取目标文件出错: %v\n", err)
		os.Exit(1)
	}

	if len(targets) == 0 {
		fmt.Println("[-] 未找到有效的目标")
		return
	}
	fmt.Printf("[+] 加载 %d 个目标，并发数 %d\n", len(targets), cfg.Concurrency)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	tr := tracer.NewTracer(cfg.Timeout, cfg.MaxHops)
	start := time.Now()
	results := worker.Run(ctx, targets, tr, matcher, cfg.Concurrency, cfg.EnablePing)
	fmt.Printf("[+] 测试完成，耗时: %v\n", time.Since(start).Round(time.Second))

	saveResults(results)
}

func isWideRune(r rune) bool {
	if r < 0x1100 {
		return false
	}
	return (r >= 0x1100 && r <= 0x115F) ||
		(r >= 0x2E80 && r <= 0xA4CF) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE1F) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x20000 && r <= 0x3FFFD)
}

func displayWidth(s string) int {
	width := 0
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if isWideRune(r) {
			width += 2
		} else {
			width += 1
		}
	}
	return width
}

func padCell(s string, targetWidth int, rightAlign bool) string {
	w := displayWidth(s)
	pad := targetWidth - w
	if pad < 0 {
		pad = 0
	}
	spaces := strings.Repeat(" ", pad)
	if rightAlign {
		return " " + spaces + s + " "
	}
	return " " + s + spaces + " "
}

func saveResults(results []worker.Result) {
	if len(results) == 0 {
		fmt.Println("[-] 无有效结果")
		return
	}

	headers := []string{"IP/域名", "端口", "归属运营商", "线路类型", "命中ASN", "延迟(ms)"}
	var rows [][]string
	for _, r := range results {
		ipDisplay := r.IP
		if r.Country != "" {
			ipDisplay += "#" + r.Country
		}
		if r.Err != nil {
			ipDisplay += " (异常)"
		}
		rows = append(rows, []string{ipDisplay, r.Port, r.ISP, r.LineType, r.ASNStr, r.Delay})
	}

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = displayWidth(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			if w := displayWidth(cell); w > colWidths[i] {
				colWidths[i] = w
			}
		}
	}

	makeSeparator := func(char string) string {
		var sb strings.Builder
		sb.WriteString("+")
		for _, w := range colWidths {
			sb.WriteString(strings.Repeat(char, w+2))
			sb.WriteString("+")
		}
		return sb.String()
	}

	formatRow := func(row []string, alignDataRight bool) string {
		var sb strings.Builder
		sb.WriteString("|")
		for i, cell := range row {
			right := alignDataRight && (i == 1 || i == 5)
			sb.WriteString(padCell(cell, colWidths[i], right))
			sb.WriteString("|")
		}
		return sb.String()
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("result_%s.txt", timestamp)
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[-] 无法创建结果文件: %v\n", err)
		return
	}
	defer f.Close()

	_, _ = f.WriteString("\xEF\xBB\xBF")

	sepLine := makeSeparator("-")
	sepEqual := makeSeparator("=")

	lines := []string{sepLine, formatRow(headers, false), sepEqual}
	for _, r := range rows {
		lines = append(lines, formatRow(r, true))
	}
	lines = append(lines, sepLine)

	outputStr := strings.Join(lines, "\n") + "\n"
	if _, err := f.WriteString(outputStr); err != nil {
		fmt.Printf("[-] 写入结果文件失败: %v\n", err)
		return
	}
	fmt.Print(outputStr)
	fmt.Printf("\n[+] 已保存结果至: %s\n", filename)
}
