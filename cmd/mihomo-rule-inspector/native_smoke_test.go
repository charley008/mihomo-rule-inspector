package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/mihomo"
	"mihomo-rule-inspector/internal/probe"
	"mihomo-rule-inspector/internal/server"
)

func TestNativeSmoke(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			fmt.Fprint(w, `{"version":"fixture"}`)
		case "/configs":
			fmt.Fprint(w, `{}`)
		case "/rules":
			fmt.Fprint(w, `{"rules":[{"type":"DOMAIN","payload":"example.com","proxy":"DIRECT"}]}`)
		case "/providers/rules":
			fmt.Fprint(w, `{"providers":{"fixture":{"ruleCount":1}}}`)
		case "/connections":
			fmt.Fprint(w, `{"connections":[{"metadata":{"host":"example.com","destinationIP":"192.0.2.1","destinationPort":"443"},"rule":"DOMAIN","chains":["DIRECT"]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()
	cfg := config.Default()
	cfg.ControllerURL = controller.URL
	ctx := context.Background()
	health, err := server.CheckController(ctx, cfg)
	if err != nil || health["ok"] != true {
		t.Fatalf("health: %v, %v", health, err)
	}
	rules, err := server.Rules(ctx, cfg, "example.com")
	if err != nil || len(rules.Candidates) != 1 {
		t.Fatalf("rules: %+v, %v", rules, err)
	}
	client, err := mihomo.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := client.GetConnections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	app := newInspector(ctx, cfg)
	defer app.logs.Stop()
	app.historyPath = filepath.Join(t.TempDir(), "history.json")
	app.history = []probe.Diagnosis{{Target: "example.com", NormalizedHost: "example.com", Verdict: "DIRECT"}}
	app.saveHistory()
	if _, err := os.Stat(app.historyPath); err != nil {
		t.Fatal(err)
	}
	app.batch.value = app.history
	app.batch.ready = true
	app.health.value, app.health.ready = health, true
	app.rules.value, app.rules.ready = rules, true
	app.connections.value, app.connections.ready = connections, true
	app.nextConnection = time.Now().Add(time.Minute)
	app.lightMode = false
	app.themePath = filepath.Join(t.TempDir(), "theme.txt")
	tester := ui.NewTester(app.view, 950, 640)
	if !tester.HasText(appVersion) {
		t.Fatalf("missing application version %q", appVersion)
	}
	dark := tester.Image().RGBAAt(4, 600)
	if err := tester.Click("浅色模式"); err != nil {
		t.Fatal(err)
	}
	light := tester.Image().RGBAAt(4, 600)
	if !app.lightMode || !tester.HasText("深色模式") || light.R <= dark.R {
		t.Fatal("light theme did not apply")
	}
	reloaded := &inspector{}
	reloaded.loadTheme(filepath.Join(filepath.Dir(app.themePath), "config.json"))
	if !reloaded.lightMode {
		t.Fatal("light theme preference was not saved")
	}
	if err := tester.Click("深色模式"); err != nil {
		t.Fatal(err)
	}
	if app.lightMode || !tester.HasText("浅色模式") {
		t.Fatal("dark theme did not apply")
	}
	for _, tc := range []struct{ tab, want string }{
		{"批量检测", "最终节点"}, {"实时连接", "当前 1 条连接"},
		{"日志", "清空"}, {"规则浏览", "1 条规则，1 条候选匹配"},
		{"设置", "配置文件路径"}, {"快速检测", "历史记录"},
	} {
		if err := tester.Click(tc.tab); err != nil {
			t.Fatal(err)
		}
		if !tester.HasText(tc.want) {
			t.Fatalf("%s: missing %q in %q", tc.tab, tc.want, tester.Texts())
		}
	}
}
