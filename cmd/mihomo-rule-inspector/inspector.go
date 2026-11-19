package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
	"mihomo-rule-inspector/internal/probe"
	"mihomo-rule-inspector/internal/server"
)

type inspector struct {
	ctx                                                    context.Context
	window                                                 *mygo.Window
	logs                                                   *server.LogCollector
	logConfig                                              atomic.Pointer[config.AppConfig]
	active                                                 int
	settings, cfg                                          config.AppConfig
	cfgTimeout, timeout, target, batchTargets, rulesTarget string
	clearDNS, clearFakeIP                                  bool
	connectionFilter, logFilter                            string
	quick                                                  task[probe.Diagnosis]
	batch                                                  task[[]probe.Diagnosis]
	health                                                 task[map[string]any]
	rules                                                  task[server.RulesResult]
	connections                                            task[map[string]any]
	export                                                 task[string]
	nextConnection                                         time.Time

	configPath, historyPath, settingsStatus, historyStatus string
	history                                                []probe.Diagnosis
	connectionsUpdated                                     time.Time
	evidenceOpen                                           bool
	lightMode                                              bool
	themePath, themeStatus                                 string
}

type task[T any] struct {
	value       T
	busy, ready bool
	err         error
}

func runTask[T any](window *mygo.Window, task *task[T], run func() (T, error), done func(T)) {
	if task.busy {
		return
	}
	task.busy = true
	task.err = nil
	go func() {
		value, err := run()
		window.Update(func() {
			task.busy = false
			task.err = err
			if err == nil {
				task.value, task.ready = value, true
				if done != nil {
					done(value)
				}
			}
		})
	}()
}

func newInspector(ctx context.Context, cfg config.AppConfig) *inspector {
	path, _ := config.Path()
	s := &inspector{
		ctx: ctx, cfg: cfg, settings: cfg, cfgTimeout: strconv.Itoa(cfg.TimeoutMs),
		timeout: strconv.Itoa(cfg.TimeoutMs), clearDNS: cfg.ClearDNSCacheBeforeProbe,
		clearFakeIP: cfg.ClearFakeIPCacheBeforeProbe, target: "www.google.com",
		batchTargets: "www.qq.com\nwww.google.com\nwww.chatgpt.com", configPath: path,
		historyPath: filepath.Join(filepath.Dir(path), "history.json"),
	}
	s.logConfig.Store(&cfg)
	s.loadTheme(path)
	s.logs = server.NewLogCollector(func() config.AppConfig { return *s.logConfig.Load() })
	if data, err := os.ReadFile(s.historyPath); err == nil {
		if err := json.Unmarshal(data, &s.history); err != nil {
			s.history = nil
			s.historyStatus = err.Error()
		}
	} else if !os.IsNotExist(err) {
		s.historyStatus = err.Error()
	}
	return s
}

func (s *inspector) probeRequest() probe.ProbeRequest {
	return probe.ProbeRequest{
		Target: strings.TrimSpace(s.target), TimeoutMs: positiveInt(s.timeout, s.cfg.TimeoutMs),
		ClearDNSCache: s.clearDNS, ClearFakeIPCache: s.clearFakeIP,
	}
}

func (s *inspector) startQuick() {
	cfg, req := s.cfg, s.probeRequest()
	if req.Target == "" {
		return
	}
	runTask(s.window, &s.quick, func() (probe.Diagnosis, error) {
		service, err := probe.NewService(cfg)
		if err != nil {
			return probe.Diagnosis{}, err
		}
		return service.Run(s.ctx, req)
	}, func(result probe.Diagnosis) {
		s.evidenceOpen = false
		if len(result.RawConnection) == 0 {
			return
		}
		s.history = append([]probe.Diagnosis{result}, s.history...)
		if len(s.history) > 20 {
			s.history = s.history[:20]
		}
		s.saveHistory()
	})
}

func (s *inspector) saveHistory() {
	err := os.WriteFile(s.historyPath, []byte(jsonText(s.history)), 0o600)
	s.historyStatus = ""
	if err != nil {
		s.historyStatus = "保存历史失败：" + err.Error()
	}
}

func positiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func jsonText(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(data)
}

func taskStatus[T any](c *ui.Context, task *task[T], waiting string) {
	if task.busy {
		ui.Text(c, waiting).TextColor(c.Theme().TextMuted)
	} else if task.err != nil {
		ui.Text(c, task.err.Error()).Wrap().Selectable()
	}
}

func details(c *ui.Context, value string, height float32) {
	ui.TextArea(c, &value).ReadOnly(true).FillWidth().Height(height)
}

func (s *inspector) diagnosisView(c *ui.Context) {
	result := s.quick.value
	verdict := firstValue(result.Verdict, "UNKNOWN")
	quickCard(c.Key("diagnosis")).
		Padding(16).Radius(24).Gap(12).Gradient(c.Theme().Surface, c.Theme().Background, 180).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(16).Children(func() {
			ui.Column(c).Grow(1).Gap(4).Children(func() {
				label(c, firstValue(result.Target, "未提供目标")).FontSize(21).Bold().Wrap()
				label(c, fallback(result.NormalizedHost)).TextColor(c.Theme().TextMuted).Selectable()
			})
			verdictBadge(c, verdict, statusLabel(result))
		})
		ui.Column(c).FillWidth().Grid().Columns(4).Gap(10).Children(func() {
			fields := []struct{ name, value string }{
				{"规则类型", result.RuleType}, {"规则内容", result.RulePayload},
				{"策略组", result.Policy}, {"最终节点", result.FinalProxy},
				{"Chains", strings.Join(result.Chains, " / ")}, {"网络", result.Network},
				{"目标端口", ""}, {"耗时", fmt.Sprintf("%d ms", result.DurationMs)},
			}
			if result.DstPort != 0 {
				fields[6].value = strconv.Itoa(result.DstPort)
			}
			for _, field := range fields {
				ui.Column(c).FillWidth().MinWidth(0).Gap(4).Children(func() {
					label(c, field.name).TextColor(c.Theme().TextMuted)
					label(c, fallback(field.value)).FillWidth().Bold().Wrap().Selectable()
				})
			}
		})
		if result.Error != "" {
			label(c, result.Error).FillWidth().Padding(9, 11).FontSize(14).TextColor(palette(c).errorText).
				Background(palette(c).errorFill).Radius(12).Wrap().Selectable()
		}
		for _, suggestion := range result.Suggestions {
			hint(c, suggestion)
		}
		caption := "▸ 原始证据"
		if s.evidenceOpen {
			caption = "▾ 原始证据"
		}
		if button(c.Key("evidence-toggle"), caption, false).AlignSelf(ui.Start).Label("原始证据").Clicked() {
			s.evidenceOpen = !s.evidenceOpen
		}
		if s.evidenceOpen {
			details(c.Key("evidence"), jsonText(map[string]any{
				"rawLogs": result.RawLogs, "rawConnection": result.RawConnection,
				"dnsResult": result.DNSResult, "error": result.Error,
			}), 190)
		}
	})
}

func statusLabel(result probe.Diagnosis) string {
	if result.Verdict == "PROXY" && result.Policy != "" {
		return result.Policy
	}
	return firstValue(result.Verdict, result.Policy, "UNKNOWN")
}

func (s *inspector) checkController(cfg config.AppConfig) {
	runTask(s.window, &s.health, func() (map[string]any, error) {
		return server.CheckController(s.ctx, cfg)
	}, nil)
}

func (s *inspector) refreshConnections() {
	cfg := s.cfg
	s.nextConnection = time.Now().Add(time.Second)
	runTask(s.window, &s.connections, func() (map[string]any, error) {
		client, err := mihomo.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		return client.GetConnections(ctx)
	}, func(map[string]any) { s.connectionsUpdated = time.Now() })
}

func field(m map[string]any, name string) string {
	if value := m[name]; value != nil {
		return fmt.Sprint(value)
	}
	return ""
}
