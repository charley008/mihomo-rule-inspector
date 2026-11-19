package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
	"mihomo-rule-inspector/internal/probe"
	"mihomo-rule-inspector/internal/server"
)

const quickCardWidth = 650

func quickCard(c *ui.Context) ui.Element {
	return card(c).MaxWidth(quickCardWidth).AlignSelf(ui.Start)
}

func (s *inspector) quickView(c *ui.Context) {
	quickCard(c.Key("target-form")).Children(func() {
		label(c, "目标")
		ui.Row(c).FillWidth().Gap(12).Children(func() {
			input(c, &s.target).Width(420).MinWidth(0).Label("目标").
				Placeholder("例如 api.openai.com 或 https://api.openai.com/v1").OnSubmit(s.startQuick)
			if button(c, "开始检测", true).Disabled(s.quick.busy).Clicked() {
				s.startQuick()
			}
		})
		ui.Row(c).FillWidth().Gap(14).AlignItems(ui.Center).Children(func() {
			cacheOption(c.Key("dns"), &s.clearDNS, "检测前清理 DNS cache")
			cacheOption(c.Key("fake-ip"), &s.clearFakeIP, "检测前清理 fake-ip cache")
			label(c, "超时\n(ms)").Width(40).TextColor(c.Theme().TextMuted)
			input(c, &s.timeout).Label("探测超时（毫秒）").Width(96)
		})
		taskStatus(c, &s.quick, "正在检测，请稍候…")
	})
	if s.quick.ready {
		s.diagnosisView(c)
	}
	quickCard(c.Key("history")).Children(func() {
		ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
			label(c, "历史记录").FontSize(18).Bold().Grow(1)
			if button(c, "清空历史", false).Disabled(len(s.history) == 0).Clicked() {
				s.history = nil
				s.saveHistory()
			}
		})
		if s.historyStatus != "" {
			hint(c, s.historyStatus)
		}
		if len(s.history) == 0 {
			label(c, "暂无历史记录").TextColor(c.Theme().TextMuted)
		}
		diagnosisTable(c, s.history, min(quickCardWidth-32, tableWidth(c)), s.quick.busy, func(item probe.Diagnosis) {
			s.target = firstValue(item.Target, item.NormalizedHost)
			s.quick.value, s.quick.ready, s.quick.err = item, true, nil
			s.evidenceOpen = false
			c.Invalidate()
		})
	})
}

func cacheOption(c *ui.Context, checked *bool, caption string) {
	ui.Row(c).Width(184).MinHeight(59).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Row(c).Grow(1).Justify(ui.Center).Children(func() {
			ui.Checkbox(c, checked, "").Label(caption)
		})
		label(c, caption).Width(80).TextColor(c.Theme().TextMuted).Wrap().OnClick(func() {
			*checked = !*checked
		})
	})
}

func (s *inspector) batchView(c *ui.Context) {
	card(c.Key("batch-form")).MaxWidth(512).AlignSelf(ui.Start).Children(func() {
		label(c, "目标列表")
		ui.TextArea(c, &s.batchTargets).FillWidth().Height(158).Label("批量目标").Placeholder("一行一个域名").
			FontSize(15).TextColor(c.Theme().Text).Background(palette(c).input).Border(1, c.Theme().Border).Radius(12).Padding(10, 11)
		ui.Row(c).Gap(12).Children(func() {
			if button(c, "开始批量检测", true).Disabled(s.batch.busy).Clicked() {
				req := s.probeRequest()
				cfg := s.cfg
				batch := probe.BatchProbeRequest{
					Targets: strings.Split(s.batchTargets, "\n"), ClearDNSCache: req.ClearDNSCache,
					ClearFakeIPCache: req.ClearFakeIPCache, TimeoutMs: req.TimeoutMs, Concurrency: 1,
				}
				runTask(s.window, &s.batch, func() ([]probe.Diagnosis, error) {
					return server.BatchProbe(s.ctx, cfg, batch)
				}, nil)
			}
			if button(c, "复制结果", false).Disabled(!s.batch.ready).Clicked() {
				c.Services().WriteClipboard(jsonText(s.batch.value))
			}
			if button(c, "导出 JSON", false).Disabled(!s.batch.ready || s.export.busy).Clicked() {
				s.exportBatch()
			}
		})
		taskStatus(c, &s.batch, "正在串行检测，请稍候…")
		taskStatus(c, &s.export, "正在导出…")
		if s.export.value != "" && s.export.err == nil {
			hint(c, "已导出至 "+s.export.value)
		}
	})
	card(c.Key("batch-results")).Children(func() {
		diagnosisTable(c, s.batch.value, tableWidth(c), false, nil)
	})
}

func diagnosisTable(c *ui.Context, results []probe.Diagnosis, width float32, disabled bool, open func(probe.Diagnosis)) {
	widths := []float32{.19, .18, .23, .16, .12, .12}
	tableRow(c, []string{"域名", "策略组", "规则类型/内容", "最终节点", "耗时", "错误"}, widths, width, true)
	for i, item := range results {
		host := fallback(firstValue(item.NormalizedHost, item.Target))
		render := func() {
			tableRow(c, []string{host, statusLabel(item), ruleLabel(item.RuleType, item.RulePayload),
				fallback(item.FinalProxy), fmt.Sprintf("%d ms", item.DurationMs), item.Error},
				widths, width, false, firstValue(item.Verdict, "UNKNOWN")).IgnoreInput(open != nil)
		}
		if open == nil {
			render()
		} else if ui.ButtonBase(c.Key(i)).Label(host).FillWidth().Disabled(disabled).Children(render).Clicked() {
			open(item)
		}
	}
}

func (s *inspector) exportBatch() {
	results := s.batch.value
	runTask(s.window, &s.export, func() (string, error) {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent: s.window, Title: "导出批量检测结果", DefaultPath: "batch-results.json",
			Filters: []mygo.FileFilter{{Name: "JSON", Extensions: []string{"json"}}},
		})
		if err != nil || path == "" {
			return "", err
		}
		return path, os.WriteFile(path, []byte(jsonText(results)), 0o600)
	}, nil)
}

func (s *inspector) connectionsView(c *ui.Context) {
	if !s.connections.busy && s.window != nil {
		if delay := time.Until(s.nextConnection); delay > 0 {
			c.After(delay)
		} else {
			s.refreshConnections()
		}
	}
	rows := mapsFrom(s.connections.value["connections"])
	card(c.Key("connection-filter")).MaxWidth(520).AlignSelf(ui.Start).Children(func() {
		ui.Row(c).FillWidth().Gap(12).Children(func() {
			input(c, &s.connectionFilter).Width(340).MinWidth(0).Label("连接过滤").Placeholder("按 host 过滤")
			if button(c, "刷新快照", false).Disabled(s.connections.busy).Clicked() {
				s.refreshConnections()
			}
		})
		switch {
		case s.connections.err != nil:
			hint(c, "连接列表刷新失败："+s.connections.err.Error())
		case s.connections.ready:
			hint(c, fmt.Sprintf("自动刷新中，最近更新：%s，当前 %d 条连接", s.connectionsUpdated.Format("15:04:05"), len(rows)))
		default:
			hint(c, "自动刷新中...")
		}
	})
	filter := strings.ToLower(strings.TrimSpace(s.connectionFilter))
	visible := rows[:0]
	for _, row := range rows {
		metadata, _ := row["metadata"].(map[string]any)
		host := firstValue(field(metadata, "host"), field(row, "host"))
		if strings.Contains(strings.ToLower(host), filter) {
			visible = append(visible, row)
		}
	}
	sort.SliceStable(visible, func(i, j int) bool { return connectionStart(visible[i]).After(connectionStart(visible[j])) })
	card(c.Key("connection-table")).Gap(0).Children(func() {
		width := tableWidth(c)
		widths := []float32{.26, .062, .062, .067, .067, .10, .11, .07, .137, .065}
		tableRow(c, []string{"主机", "下载量", "上传量", "下载速度", "上传速度", "链路", "规则", "连接时间", "目标地址", "类型"}, widths, width, true)
		for _, row := range visible {
			tableRow(c, connectionCells(row), widths, width, false)
		}
	})
}

func connectionCells(row map[string]any) []string {
	metadata, _ := row["metadata"].(map[string]any)
	host := firstValue(field(metadata, "host"), field(row, "host"))
	port := firstValue(field(metadata, "destinationPort"), field(row, "dstPort"))
	destination := firstValue(field(metadata, "destinationIP"), field(metadata, "remoteDestination"), field(row, "destinationIP"), field(row, "destination"))
	up := firstValue(field(metadata, "uploadSpeed"), field(row, "uploadSpeed"), field(row, "up"))
	down := firstValue(field(metadata, "downloadSpeed"), field(row, "downloadSpeed"), field(row, "down"))
	kind := firstValue(field(metadata, "type"), field(row, "type"))
	if kind == "" {
		kind = strings.ToUpper(firstValue(field(metadata, "network"), field(row, "network")))
		if kind == "TCP" {
			kind = "HTTPS(tcp)"
		}
	}
	chains, ok := row["chains"].([]any)
	if !ok {
		chains, _ = metadata["chains"].([]any)
	}
	var display []string
	seen := make(map[string]bool)
	add := func(name string) {
		name = strings.TrimSpace(name)
		lower := strings.ToLower(name)
		if name != "" && !seen[lower] {
			seen[lower] = true
			display = append(display, name)
		}
	}
	add(field(metadata, "specialProxy"))
	for i := len(chains) - 1; i >= 0; i-- {
		if name, ok := chains[i].(string); ok {
			add(name)
		}
	}
	add(field(row, "outbound"))
	return []string{address(host, port), formatBytes(field(row, "download")), formatBytes(field(row, "upload")),
		formatBytes(down) + "/s", formatBytes(up) + "/s", fallback(strings.Join(display, " / ")),
		ruleLabel(firstValue(field(metadata, "rule"), field(row, "rule")), firstValue(field(metadata, "rulePayload"), field(row, "rulePayload"))),
		relativeTime(connectionStart(row)), address(destination, port), fallback(kind)}
}

func connectionStart(row map[string]any) time.Time {
	start, _ := time.Parse(time.RFC3339Nano, field(row, "start"))
	return start
}

func relativeTime(start time.Time) string {
	if start.IsZero() {
		return "-"
	}
	seconds := max(0, int(time.Since(start).Seconds()))
	switch {
	case seconds < 60:
		return fmt.Sprintf("%d 秒前", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%d 分钟前", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%d 小时前", seconds/3600)
	default:
		return fmt.Sprintf("%d 天前", seconds/86400)
	}
}

func address(host, port string) string {
	if host == "" || port == "" {
		return fallback(host)
	}
	return net.JoinHostPort(host, port)
}

func formatBytes(value string) string {
	n, _ := strconv.ParseFloat(value, 64)
	if n < 1024 {
		return fmt.Sprintf("%.0f B", max(0, n))
	}
	for _, unit := range []string{"KB", "MB", "GB", "TB"} {
		n /= 1024
		if n < 1024 || unit == "TB" {
			precision := 2
			if n >= 100 {
				precision = 0
			} else if n >= 10 {
				precision = 1
			}
			return fmt.Sprintf("%.*f %s", precision, n, unit)
		}
	}
	return "0 B"
}

var logKeywords = regexp.MustCompile("(?i)match|using|direct|reject|proxy|rule")

func (s *inspector) logsView(c *ui.Context) {
	card(c.Key("log-filter")).MaxWidth(460).AlignSelf(ui.Start).Children(func() {
		ui.Row(c).FillWidth().Gap(12).Children(func() {
			input(c, &s.logFilter).Width(320).MinWidth(0).Label("日志过滤").Placeholder("关键词过滤")
			if button(c, "清空", false).Clicked() {
				s.logs.Clear()
			}
		})
	})
	c.After(time.Second)
	filter := strings.ToLower(strings.TrimSpace(s.logFilter))
	ui.Column(c.Key("log-view")).FillWidth().Padding(11).Radius(12).Background(palette(c).sidebar).Border(1, c.Theme().Border).Children(func() {
		for _, line := range s.logs.Snapshot(300) {
			if strings.Contains(strings.ToLower(line), filter) {
				logLine(c, line)
			}
		}
	})
}

func logLine(c *ui.Context, line string) {
	ui.RichText(c).FillWidth().FontSize(14).TextColor(c.Theme().Text).Wrap().Selectable().Children(func() {
		pos := 0
		for _, match := range logKeywords.FindAllStringIndex(line, -1) {
			ui.Text(c, line[pos:match[0]])
			ui.Text(c, line[match[0]:match[1]]).TextColor(palette(c).highlightText).Background(palette(c).highlight).Radius(4)
			pos = match[1]
		}
		ui.Text(c, line[pos:])
	})
}

func (s *inspector) loadRules() {
	cfg, target := s.cfg, s.rulesTarget
	runTask(s.window, &s.rules, func() (server.RulesResult, error) {
		return server.Rules(s.ctx, cfg, target)
	}, nil)
}

func (s *inspector) rulesView(c *ui.Context) {
	result := s.rules.value
	rows := mapsFrom(result.Rules["rules"])
	card(c.Key("rules-filter")).MaxWidth(520).AlignSelf(ui.Start).Children(func() {
		ui.Row(c).FillWidth().Gap(12).Children(func() {
			input(c, &s.rulesTarget).Width(340).MinWidth(0).Label("候选域名").Placeholder("输入域名做候选匹配").OnSubmit(s.loadRules)
			if button(c, "加载规则", false).Disabled(s.rules.busy).Clicked() {
				s.loadRules()
			}
		})
		switch {
		case s.rules.busy:
			hint(c, "正在加载规则...")
		case s.rules.err != nil:
			hint(c, "规则加载失败："+s.rules.err.Error())
		case result.RulesError != "":
			hint(c, "规则加载失败："+result.RulesError)
		case s.rules.ready:
			hint(c, fmt.Sprintf("规则加载完成：%d 条规则，%d 条候选匹配", len(rows), len(result.Candidates)))
		default:
			hint(c, "切换到规则浏览时会自动加载规则，也可以手动刷新。")
		}
	})
	matches := make(map[int]string, len(result.Candidates))
	card(c.Key("rules-table")).Gap(0).Children(func() {
		ui.Row(c).FillWidth().Wrap().Gap(8).Padding(0, 0, 12).Children(func() {
			for _, item := range result.Candidates {
				index, ok := item["index"].(int)
				if !ok {
					continue
				}
				matches[index] = field(item, "matchType")
				label(c, fmt.Sprintf("#%d %s %s (%s)", index, field(item, "type"), field(item, "payload"), matches[index])).
					Padding(5, 9).FontSize(13).TextColor(palette(c).detailText).Background(palette(c).chip).Radius(999)
			}
		})
		width := tableWidth(c)
		widths := []float32{.065, .225, .45, .12, .14}
		tableRow(c, []string{"#", "Type", "Payload", "Policy", "匹配提示"}, widths, width, true)
		for i, row := range rows {
			tableRow(c, []string{strconv.Itoa(i), field(row, "type"), field(row, "payload"), field(row, "proxy"), matches[i]}, widths, width, false)
		}
	})
}

func (s *inspector) settingsView(c *ui.Context) {
	cfg := &s.settings

	mode := "HTTP Controller"
	if cfg.ControllerMode == config.ControllerModeWindowsPipe {
		mode = "Windows Pipe"
	}
	card(c.Key("settings-form")).MaxWidth(640).AlignSelf(ui.Start).Children(func() {
		settingsRow(c.Key("mode"), "Controller 模式", func() {
			if ui.Select(c, &mode, []string{"HTTP Controller", "Windows Pipe"}).Label("Controller 模式").
				Width(202).MinWidth(0).Height(40).Radius(12).Background(palette(c).input).Border(1, c.Theme().Border).
				FontSize(15).TextColor(c.Theme().Text).Changed() {
				cfg.ControllerMode = config.ControllerModeHTTP
				if mode == "Windows Pipe" {
					cfg.ControllerMode = config.ControllerModeWindowsPipe
				}
			}
		})
		settingsInput(c.Key("url"), "HTTP Controller 地址", &cfg.ControllerURL, 328, false)
		settingsInput(c.Key("pipe"), "Windows Pipe 名称", &cfg.ControllerPipe, 300, false)
		settingsInput(c.Key("secret"), "Secret", &cfg.Secret, 250, true)
		settingsInput(c.Key("proxy"), "Mixed Proxy 地址", &cfg.MixedProxyURL, 328, false)
		settingsInput(c.Key("timeout"), "默认超时 (ms)", &s.cfgTimeout, 96, false)
		ui.Checkbox(c, &cfg.ClearDNSCacheBeforeProbe, "默认检测前清理 DNS cache").FontSize(15).TextColor(c.Theme().Text).AlignSelf(ui.Start)
		ui.Checkbox(c, &cfg.ClearFakeIPCacheBeforeProbe, "默认检测前清理 fake-ip cache").FontSize(15).TextColor(c.Theme().Text).AlignSelf(ui.Start)
		settingsBox(c.Key("config-path"), "配置文件路径", s.configPath)
		var controller mihomo.ControllerInfo
		if s.health.err == nil {
			controller, _ = s.health.value["controller"].(mihomo.ControllerInfo)
		}
		settingsBox(c.Key("controller"), "当前 Controller", fallback(controller.DisplayName))
		ui.Row(c.Key("settings-actions")).Gap(12).Children(func() {
			if button(c, "保存配置", true).Clicked() {
				s.saveConfig()
			}
			if button(c, "测试连接", false).Disabled(s.health.busy).Clicked() {
				s.checkController(s.settingsDraft())
			}
		})
		status := ""
		switch {
		case s.health.busy:
			status = "正在测试连接..."
		case s.health.err != nil:
			status = "连接失败。\n" + s.health.err.Error()
		case s.health.ready && s.health.value["ok"] == true:
			status = "连接成功。\n" + controller.DisplayName
		case s.health.ready:
			status = "连接失败。\n" + jsonText(s.health.value["errors"])
		}
		if status != "" {
			hint(c, status)
		}
		if s.settingsStatus != "" {
			hint(c, s.settingsStatus)
		}
	})
}

func settingsInput(c *ui.Context, name string, value *string, width float32, secret bool) {
	settingsRow(c, name, func() {
		element := input(c, value).Label(name).Width(width).MinWidth(0)
		if secret {
			element.Password().Placeholder("Bearer secret")
		}
	})
}

func settingsRow(c *ui.Context, name string, control func()) {
	ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
		label(c, name).Width(168).Shrink(0).Wrap()
		control()
	})
}

func settingsBox(c *ui.Context, title, value string) {
	ui.Column(c).FillWidth().MinWidth(0).Padding(12).Gap(6).Background(palette(c).input).Border(1, c.Theme().Border).Radius(12).Children(func() {
		label(c, title).Bold()
		label(c, value).FillWidth().Wrap().Selectable().Font("Consolas").TextColor(palette(c).detailText)
	})
}

func tableWidth(c *ui.Context) float32 {
	windowWidth, _ := c.Size()
	return windowWidth - 260 - 48 - 32
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func fallback(value string) string {
	return firstValue(value, "-")
}

func trimRule(value string) string {
	return strings.TrimLeft(strings.TrimSpace(value), "- ")
}
func (s *inspector) settingsDraft() config.AppConfig {
	cfg := s.settings
	cfg.ControllerURL = strings.TrimSpace(cfg.ControllerURL)
	cfg.ControllerPipe = strings.TrimSpace(cfg.ControllerPipe)
	cfg.MixedProxyURL = strings.TrimSpace(cfg.MixedProxyURL)
	cfg.TimeoutMs = positiveInt(s.cfgTimeout, config.Default().TimeoutMs)
	return cfg
}

func (s *inspector) saveConfig() {
	cfg := s.settingsDraft()
	if err := config.Save(cfg); err != nil {
		s.settingsStatus = "保存失败：" + err.Error()
		return
	}
	saved, err := config.Load()
	if err != nil {
		s.settingsStatus = "读取配置失败：" + err.Error()
		return
	}
	s.cfg, s.settings = saved, saved
	s.timeout, s.cfgTimeout = strconv.Itoa(saved.TimeoutMs), strconv.Itoa(saved.TimeoutMs)
	s.clearDNS, s.clearFakeIP = saved.ClearDNSCacheBeforeProbe, saved.ClearFakeIPCacheBeforeProbe
	s.logConfig.Store(&saved)
	s.logs.Restart()
	s.settingsStatus = "配置已保存"
	s.nextConnection = time.Time{}
}

func mapsFrom(value any) []map[string]any {
	raw, _ := value.([]any)
	rows := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if row, ok := item.(map[string]any); ok {
			rows = append(rows, row)
		}
	}
	return rows
}
