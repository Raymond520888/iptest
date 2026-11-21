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
	var (
		inputFile   = flag.String("f", "testdata/ips.txt", "目标文件路径")
		conc        = flag.Int("c", 128, "并发数")
		timeout     = flag.Duration("timeout", 120*time.Second, "单次追踪超时")
		maxHops     = flag.Int("m", 30, "最大跳数")
		enablePing  = flag.Bool("ping", false, "启用延迟测试")
		forceUpdate = flag.Bool("update", false, "强制从 RIPEstat 更新前缀表数据") // 新增这一行
	)

	fmt.Printf("IP Batch Track %s (commit: %s)\n", version, commit)
	flag.Parse()

	// 修改前缀表检测逻辑：支持 -update 强制更新，或文件不存在时自动更新
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

	file, err := os.Open(*inputFile)
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

	if len(targets) == 0 {
		fmt.Println("[-] 未找到有效的目标")
		return
	}
	fmt.Printf("[+] 加载 %d 个目标，并发数 %d\n", len(targets), *conc)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	tr := tracer.NewTracer(*timeout, *maxHops)
	start := time.Now()
	results := worker.Run(ctx, targets, tr, matcher, *conc, *enablePing)
	fmt.Printf("[+] 测试完成，耗时: %v\n", time.Since(start).Round(time.Second))

	saveResults(results)
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
		delay := r.Delay
		if r.Err != nil {
			ipDisplay = r.IP + " (异常)"
		}
		rows = append(rows, []string{ipDisplay, r.Port, r.ISP, r.LineType, r.ASNStr, delay})
	}

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
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

	formatRow := func(row []string, alignRight bool) string {
		var sb strings.Builder
		sb.WriteString("|")
		for i, cell := range row {
			var padded string
			if alignRight && (i == 1 || i == 5) {
				padded = fmt.Sprintf(" %*s ", colWidths[i], cell)
			} else {
				padded = fmt.Sprintf(" %-*s ", colWidths[i], cell)
			}
			sb.WriteString(padded)
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
	f.WriteString("\xEF\xBB\xBF")

	sepLine := makeSeparator("-")
	sepEqual := makeSeparator("=")

	lines := []string{sepLine, formatRow(headers, false), sepEqual}
	for _, r := range rows {
		lines = append(lines, formatRow(r, true))
	}
	lines = append(lines, sepLine)

	outputStr := strings.Join(lines, "\n") + "\n"
	f.WriteString(outputStr)
	fmt.Print(outputStr)
	fmt.Printf("\n[+] 已保存结果至: %s\n", filename)
}
