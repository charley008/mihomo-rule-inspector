package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo/ui"
)

type appPalette struct {
	theme                                                            ui.Theme
	sidebar, panel, input, glow                                      ui.Color
	highlight, highlightText, chip, detailText, errorFill, errorText ui.Color
}

var darkPalette = appPalette{
	theme:   inspectorTheme(*ui.DarkTheme(), "#0c1218", "#17232f", "#263849", "#e8f0f6", "#93a8ba"),
	sidebar: ui.Hex("#0b1219"), panel: ui.Hex("#121c25"), input: ui.Hex("#0e1720"),
	glow:      ui.Hex("#111f33"),
	highlight: ui.Hex("#3e3217"), highlightText: ui.Hex("#fde68a"),
	chip: ui.Hex("#152a47"), detailText: ui.Hex("#bfdbfe"),
	errorFill: ui.Hex("#38191d"), errorText: ui.Hex("#fecaca"),
}

var lightPalette = appPalette{
	theme:   inspectorTheme(*ui.LightTheme(), "#f3f7fb", "#e9eff6", "#c6d3e0", "#142534", "#40576a"),
	sidebar: ui.Hex("#edf3f8"), panel: ui.Hex("#ffffff"), input: ui.Hex("#f8fafc"),
	glow:      ui.Hex("#dceafb"),
	highlight: ui.Hex("#fff0b7"), highlightText: ui.Hex("#604600"),
	chip: ui.Hex("#e0edff"), detailText: ui.Hex("#204d79"),
	errorFill: ui.Hex("#fce7e7"), errorText: ui.Hex("#922529"),
}

func inspectorTheme(base ui.Theme, background, surface, border, text, muted string) ui.Theme {
	base.Background = ui.Hex(background)
	base.Surface = ui.Hex(surface)
	base.Border = ui.Hex(border)
	base.Text = ui.Hex(text)
	base.TextMuted = ui.Hex(muted)
	return base
}

func palette(c *ui.Context) *appPalette {
	if c.Theme().Dark {
		return &darkPalette
	}
	return &lightPalette
}

func (s *inspector) themeControls(c *ui.Context) {
	caption := "浅色模式"
	if s.lightMode {
		caption = "深色模式"
	}
	if button(c, caption, false).FillWidth().Clicked() {
		s.lightMode = !s.lightMode
		mode := "dark"
		if s.lightMode {
			mode = "light"
		}
		s.themeStatus = ""
		if err := os.WriteFile(s.themePath, []byte(mode+"\n"), 0o600); err != nil {
			s.themeStatus = "无法保存主题：" + err.Error()
		}
		c.Invalidate()
	}
	if s.themeStatus != "" {
		label(c, s.themeStatus).FontSize(12).TextColor(c.Theme().TextMuted).Wrap()
	}
	label(c, appVersion).FontSize(12).TextColor(c.Theme().TextMuted)
}

func (s *inspector) loadTheme(configPath string) {
	s.themePath = filepath.Join(filepath.Dir(configPath), "theme.txt")
	data, err := os.ReadFile(s.themePath)
	if err == nil {
		s.lightMode = strings.TrimSpace(string(data)) == "light"
	}
}
