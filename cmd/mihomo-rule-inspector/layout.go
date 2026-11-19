package main

import "github.com/egoist/mygo/ui"

func label(c *ui.Context, value string) ui.Element {
	return ui.Text(c, value).FontSize(15).TextColor(c.Theme().Text)
}

func button(c *ui.Context, value string, primary bool) ui.Element {
	element := ui.Button(c, value).Height(40).Padding(0, 13).Radius(12).
		FontSize(15).TextColor(c.Theme().Text).Background(c.Theme().Surface).Border(1, c.Theme().Border)
	if primary {
		element.Gradient(ui.Hex("#1d4ed8"), ui.Hex("#0f766e"), 135).TextColor(ui.Hex("#ffffff")).Border(0, c.Theme().Border)
	}
	return element
}

func input(c *ui.Context, value *string) ui.Element {
	return ui.TextInput(c, value).Height(40).Padding(9, 11).Radius(12).
		FontSize(15).TextColor(c.Theme().Text).PlaceholderColor(c.Theme().TextMuted).
		Background(palette(c).input).Border(1, c.Theme().Border)
}

func card(c *ui.Context) ui.Element {
	return ui.Column(c).FillWidth().Padding(16).Gap(12).Radius(20).Background(palette(c).panel).Border(1, c.Theme().Border)
}

func hint(c *ui.Context, value string) {
	label(c, value).FillWidth().Padding(9, 11).FontSize(14).TextColor(c.Theme().TextMuted).
		Background(c.Theme().Surface).Radius(12).Wrap().Selectable()
}

func ruleLabel(kind, payload string) string {
	kind = trimRule(kind)
	payload = trimRule(payload)
	switch {
	case kind == "":
		return fallback(payload)
	case payload == "":
		return kind
	default:
		return kind + "(" + payload + ")"
	}
}

func verdictBadge(c *ui.Context, verdict, value string) {
	color := ui.Hex("#64748b")
	switch verdict {
	case "DIRECT":
		color = ui.Hex("#2f9e66")
	case "PROXY":
		color = ui.Hex("#3b82f6")
	case "REJECT":
		color = ui.Hex("#dc2626")
	}
	label(c, value).MinWidth(82).Padding(7, 11).TextAlign(ui.Center).
		Bold().TextColor(ui.Hex("#ffffff")).Background(color).Radius(999)
}

func divider(c *ui.Context) {
	ui.Row(c).FillWidth().Height(1).Background(c.Theme().Border)
}

func tableRow(c *ui.Context, values []string, widths []float32, width float32, header bool, verdict ...string) {
	ui.Column(c).FillWidth().Children(func() {
		ui.Row(c).FillWidth().Children(func() {
			for i, value := range values {
				if i == 1 && len(verdict) > 0 {
					ui.Column(c).Width(width*widths[i]).Shrink(0).Padding(8, 10).AlignItems(ui.Start).Children(func() {
						verdictBadge(c, verdict[0], value)
					})
					continue
				}
				cell := label(c, value).Width(width * widths[i]).Shrink(0).Padding(10).FontSize(14).Wrap()
				if header {
					cell.Bold()
				} else {
					cell.Selectable()
				}
			}
		})
		divider(c)
	})
}

func (s *inspector) view(c *ui.Context) {
	theme := &darkPalette.theme
	if s.lightMode {
		theme = &lightPalette.theme
	}
	c.SetTheme(theme)
	pages := []struct {
		name, description string
		render            func(*ui.Context)
	}{
		{"快速检测", "输入域名、URL 或 IP，工具会主动通过 Mihomo mixed-port 发起探测。", s.quickView},
		{"批量检测", "逐个串行探测，适合确认多条域名的真实出口，一行一个域名。", s.batchView},
		{"实时连接", "直接查看当前 Mihomo 连接、规则和链路。", s.connectionsView},
		{"日志", "辅助观察 match、using、DIRECT、REJECT 等关键词。", s.logsView},
		{"规则浏览", "前端只做弱匹配提示，最终实际命中仍以 logs 和 connections 为准。", s.rulesView},
		{"设置", "Controller 支持 HTTP Controller 和 Windows Pipe 两种模式，程序只测试你填写的目标。", s.settingsView},
	}
	ui.Column(c).Fill().Background(c.Theme().Background).Children(func() {
		s.windowBar(c)
		ui.Row(c).FillWidth().Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Width(259).Shrink(0).FillHeight().Padding(24).Gap(14).Background(palette(c).sidebar).Children(func() {
				label(c, "mihomo-rule-\ninspector").FontSize(22).Bold()
				label(c, "本地诊断面板，用来查看目标最终命中的规则、策略组和节点。").TextColor(c.Theme().TextMuted).Wrap().FillWidth()
				ui.Column(c).FillWidth().Padding(8, 0, 0).Gap(10).Children(func() {
					for i, page := range pages {
						if button(c.Key(page.name), page.name, i == s.active).FillWidth().Clicked() {
							s.active = i
							if i == 4 && s.window != nil {
								s.loadRules()
							}
						}
					}
				})
				ui.Column(c).Grow(1)
				s.themeControls(c)
			})
			ui.Column(c).FillHeight().Width(1).Shrink(0).Background(c.Theme().Border)
			page := pages[s.active]
			content := func() {
				ui.Column(c).FillWidth().Padding(24).Gap(18).Children(func() {
					ui.Column(c).FillWidth().Gap(12).Children(func() {
						label(c, page.name).FontSize(24).Bold()
						label(c, page.description).Wrap()
					})
					page.render(c)
				})
			}
			ui.Scroll(c.Key(page.name)).Grow(1).MinWidth(0).FillHeight().KeepScrollbars(true).
				Background(c.Theme().Background).RadialGradient(ui.RadialGradient{
				Center: ui.Point{X: 1}, Radius: 520,
				Stops: []ui.GradientStop{{Color: palette(c).glow, At: 0}, {Color: c.Theme().Background, At: 1}},
			}).ScrollbarInsets(0, 3).Children(content)
		})
	})
}

func (s *inspector) windowBar(c *ui.Context) {
	ui.Row(c).FillWidth().Height(39).Shrink(0).Background(palette(c).sidebar).Children(func() {
		ui.Row(c).Grow(1).FillHeight().DragWindow()
		if s.window == nil {
			return
		}
		actions := []struct {
			icon, name string
			run        func()
		}{
			{"−", "最小化", s.window.Minimize},
			{"□", "最大化或还原", func() {
				if s.window.IsMaximized() {
					s.window.Unmaximize()
				} else {
					s.window.Maximize()
				}
			}},
			{"×", "关闭", s.window.Close},
		}
		for _, action := range actions {
			if ui.Button(c.Key(action.name), action.icon).Label(action.name).Size(48, 39).
				Radius(0).FontSize(18).Background(palette(c).sidebar).Border(0, c.Theme().Border).
				TextColor(c.Theme().TextMuted).Clicked() {
				action.run()
			}
		}
	})
	divider(c)
}
