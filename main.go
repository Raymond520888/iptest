package main

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"ip-batch-track/internal/config"
	"ip-batch-track/internal/filter"
	"ip-batch-track/internal/tracer"
	"ip-batch-track/internal/worker"
)

const bannerTopRight = "ip批量路由测试 V3.0                  Make by Raymond"

var (
	version = "V3.0"
	commit  = "unknown"
)

// customTheme 支持日间浅绿风格与夜间黑夜模式切换
type customTheme struct {
	dark bool
}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if t.dark {
		switch name {
		case theme.ColorNameBackground:
			return color.NRGBA{R: 24, G: 28, B: 26, A: 255}
		case theme.ColorNameInputBackground:
			return color.NRGBA{R: 34, G: 44, B: 38, A: 255}
		case theme.ColorNameButton:
			return color.NRGBA{R: 46, G: 68, B: 54, A: 255}
		}
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}

	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 236, G: 242, B: 235, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 204, G: 228, B: 198, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 176, G: 214, B: 174, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 20, G: 28, B: 22, A: 255}
	}
	return theme.DefaultTheme().Color(name, theme.VariantLight)
}

func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *customTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func main() {
	a := app.New()
	isDark := false
	appTheme := &customTheme{dark: isDark}
	a.SetTheme(appTheme)

	w := a.NewWindow(fmt.Sprintf("批量线路测试工具 %s", version))
	w.Resize(fyne.NewSize(960, 720))

	// 右上角作者/工具标识
	topRightLabel := canvas.NewText(bannerTopRight, color.NRGBA{R: 180, G: 40, B: 40, A: 255})
	topRightLabel.TextSize = 12
	topRightLabel.TextStyle = fyne.TextStyle{Bold: true}
	topHeader := container.NewHBox(layout.NewSpacer(), topRightLabel)

	// 1. 目标输入区
	targetHint := widget.NewLabel("输入目标（每行一个，支持 IP:端口#国家，自动提取 IP/域名）：")
	targetEntry := widget.NewMultiLineEntry()
	targetEntry.SetPlaceHolder("例如：\n1.1.1.1:443#US\nexample.com:8443#JP\n8.8.8.8")

	// 2. 控制栏组件
	concEntry := widget.NewEntry()
	concEntry.SetText("128")
	concEntry.Validator = func(s string) error {
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || v <= 0 {
			return fmt.Errorf("需为正整数")
		}
		return nil
	}

	incBtn := widget.NewButton("▲", func() {
		v, _ := strconv.Atoi(strings.TrimSpace(concEntry.Text))
		if v <= 0 {
			v = 128
		}
		concEntry.SetText(strconv.Itoa(v + 16))
	})
	decBtn := widget.NewButton("▼", func() {
		v, _ := strconv.Atoi(strings.TrimSpace(concEntry.Text))
		if v > 16 {
			concEntry.SetText(strconv.Itoa(v - 16))
		} else {
			concEntry.SetText("1")
		}
	})
	spinnerBox := container.NewVBox(incBtn, decBtn)
	concBox := container.NewHBox(widget.NewLabel("并发:"), concEntry, spinnerBox)

	enablePingCheck := widget.NewCheck("启用延迟测试", nil)
	statusLabel := widget.NewLabel("就绪")

	// 3. 运行日志区
	logHint := widget.NewLabel("运行日志：")
	var (
		logMu   sync.Mutex
		logBuf  strings.Builder
		cancel  context.CancelFunc
		running bool
	)

	logEntry := widget.NewMultiLineEntry()
	logEntry.Wrapping = fyne.TextWrapWord

	appendLog := func(line string) {
		ts := time.Now().Format("15:04:05")
		msg := fmt.Sprintf("[%s] %s\n", ts, line)
		fyne.Do(func() {
			logMu.Lock()
			logBuf.WriteString(msg)
			current := logBuf.String()
			logMu.Unlock()
			logEntry.SetText(current)
			logEntry.CursorRow = len(strings.Split(current, "\n")) - 1
		})
	}

	clearLogBtn := widget.NewButton("清空日志", func() {
		logMu.Lock()
		logBuf.Reset()
		logMu.Unlock()
		logEntry.SetText("")
	})

	clearTargetBtn := widget.NewButton("清空目标", func() {
		targetEntry.SetText("")
		fyne.Do(func() { statusLabel.SetText("已清空目标") })
	})

	var updateDBBtn, startBtn, stopBtn, themeBtn *widget.Button

	setBusy := func(busy bool, statusText string) {
		running = busy
		fyne.Do(func() {
			statusLabel.SetText(statusText)
			if busy {
				startBtn.Disable()
				updateDBBtn.Disable()
				clearTargetBtn.Disable()
				stopBtn.Enable()
			} else {
				startBtn.Enable()
				updateDBBtn.Enable()
				clearTargetBtn.Enable()
				stopBtn.Disable()
			}
		})
	}

	updateDBBtn = widget.NewButton("更新前缀表 (IPv4+IPv6)", func() {
		if running {
			return
		}
		setBusy(true, "更新中...")
		appendLog("[+] 正在后台更新前缀表 (IPv4+IPv6)，请稍候...")
		go func() {
			defer setBusy(false, "就绪")
			if err := filter.UpdatePrefixDB(); err != nil {
				appendLog(fmt.Sprintf("[-] 前缀表更新失败: %v", err))
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}
			appendLog("[+] 前缀表更新完成，已自动切换至最新前缀表")
		}()
	})

	stopBtn = widget.NewButton("终止测试", func() {
		if cancel != nil {
			cancel()
			appendLog("[!] 用户请求终止测试，正在清理任务...")
			fyne.Do(func() { statusLabel.SetText("正在终止...") })
		}
	})
	stopBtn.Disable()

	startBtn = widget.NewButton("开始测试", func() {
		if running {
			return
		}
		conc, err := strconv.Atoi(strings.TrimSpace(concEntry.Text))
		if err != nil || conc <= 0 {
			dialog.ShowError(fmt.Errorf("并发数必须是大于 0 的整数"), w)
			return
		}

		rawLines := strings.Split(targetEntry.Text, "\n")
		var targets []worker.Target
		for _, line := range rawLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			ip, port, country := filter.ParseTargetLine(trimmed)
			if ip != "" {
				targets = append(targets, worker.Target{
					IP:      ip,
					Port:    port,
					Country: country,
				})
			}
		}

		if len(targets) == 0 {
			dialog.ShowInformation("提示", "请先在上方输入至少一个有效的 IP 或域名。", w)
			return
		}

		enablePing := enablePingCheck.Checked
		runCtx, runCancel := context.WithCancel(context.Background())
		cancel = runCancel

		setBusy(true, "测试中...")
		appendLog(fmt.Sprintf("[+] 已加载 %d 个目标，并发数: %d，启用延迟测试: %v", len(targets), conc, enablePing))

		go func() {
			defer func() {
				cancel = nil
				setBusy(false, "就绪")
			}()

			if _, err := os.Stat(config.DBV4Path); os.IsNotExist(err) {
				appendLog("[+] 未找到本地前缀表，正在自动拉取...")
				if err := filter.UpdatePrefixDB(); err != nil {
					appendLog(fmt.Sprintf("[-] 前缀表拉取失败: %v", err))
					return
				}
				appendLog("[+] 前缀表拉取完成")
			}

			matcher, err := filter.LoadMatcher()
			if err != nil {
				appendLog(fmt.Sprintf("[-] 加载前缀匹配器失败: %v", err))
				return
			}

			cfg := config.Config{
				Concurrency: conc,
				Timeout:     120 * time.Second,
				MaxHops:     30,
				EnablePing:  enablePing,
			}

			tr := tracer.NewTracer(cfg.Timeout, cfg.MaxHops)
			startTime := time.Now()
			results := worker.Run(runCtx, targets, tr, matcher, cfg.Concurrency, cfg.EnablePing)
			elapsed := time.Since(startTime).Round(time.Second)

			appendLog(fmt.Sprintf("[+] 测试结束，耗时 %v，共取得 %d 条结果", elapsed, len(results)))
			for _, r := range results {
				if r.Err != nil {
					appendLog(fmt.Sprintf("  - %s:%s | 异常: %v", r.IP, r.Port, r.Err))
				} else {
					appendLog(fmt.Sprintf("  - %s:%s | 运营商: %s | 线路: %s | ASN: %s | 延迟: %s",
						r.IP, r.Port, r.ISP, r.LineType, r.ASNStr, r.Delay))
				}
			}
		}()
	})

	themeBtn = widget.NewButton("🌙 黑夜模式", func() {
		isDark = !isDark
		appTheme.dark = isDark
		a.SetTheme(appTheme)
		if isDark {
			themeBtn.SetText("☀️ 日间模式")
			appendLog("[+] 已切换至黑夜模式")
		} else {
			themeBtn.SetText("🌙 黑夜模式")
			appendLog("[+] 已切换至日间模式")
		}
		canvas.Refresh(w.Content())
	})

	// 版面配置：上方目标输入 + 中间控制栏 + 下方运行日志
	controlBar := container.NewHBox(
		concBox,
		enablePingCheck,
		clearTargetBtn,
		updateDBBtn,
		startBtn,
		stopBtn,
		themeBtn,
		layout.NewSpacer(),
		statusLabel,
	)

	topSection := container.NewBorder(
		container.NewVBox(topHeader, targetHint),
		nil,
		nil,
		nil,
		targetEntry,
	)

	logHeader := container.NewHBox(logHint, layout.NewSpacer(), clearLogBtn)
	bottomSection := container.NewBorder(
		logHeader,
		nil,
		nil,
		nil,
		logEntry,
	)

	split := container.NewVSplit(topSection, bottomSection)
	split.SetOffset(0.45)

	mainLayout := container.NewBorder(
		nil,
		controlBar,
		nil,
		nil,
		split,
	)

	w.SetContent(mainLayout)
	appendLog(fmt.Sprintf("[+] 批量线路测试工具 %s 已启动", version))
	w.ShowAndRun()
}
