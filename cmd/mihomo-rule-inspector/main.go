package main

import (
	"context"
	"log"
	"net/http"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	windowsoptions "github.com/wailsapp/wails/v2/pkg/options/windows"

	"mihomo-rule-inspector/internal/config"
	"mihomo-rule-inspector/internal/server"
	webui "mihomo-rule-inspector/web"
)

func main() {
	initWindowsShellIdentity()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	apiServer := server.New(cfg)
	defer func() {
		_ = apiServer.Shutdown(context.Background())
	}()

	handler := apiServer.Handler()
	if err := wails.Run(&options.App{
		Title:                    "Mihomo Inspector",
		Width:                    1440,
		Height:                   920,
		MinWidth:                 1100,
		MinHeight:                720,
		Frameless:                true,
		BackgroundColour:         options.NewRGB(12, 18, 24),
		EnableDefaultContextMenu: false,
		Windows: &windowsoptions.Options{
			Theme:           windowsoptions.Dark,
			WindowClassName: "MihomoRuleInspectorWindow",
			CustomTheme: &windowsoptions.ThemeSettings{
				DarkModeTitleBar:          windowsoptions.RGB(12, 18, 24),
				DarkModeTitleBarInactive:  windowsoptions.RGB(19, 28, 38),
				DarkModeTitleText:         windowsoptions.RGB(232, 240, 246),
				DarkModeTitleTextInactive: windowsoptions.RGB(147, 168, 186),
				DarkModeBorder:            windowsoptions.RGB(38, 56, 73),
				DarkModeBorderInactive:    windowsoptions.RGB(27, 41, 54),
			},
		},
		AssetServer: &assetserver.Options{
			Assets: webui.Files,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r)
			}),
		},
		OnShutdown: func(ctx context.Context) {
			_ = apiServer.Shutdown(ctx)
		},
	}); err != nil {
		log.Fatalf("run app: %v", err)
	}
}
