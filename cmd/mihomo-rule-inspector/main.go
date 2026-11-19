package main

import (
	"context"
	"log"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"mihomo-rule-inspector/internal/config"
)

const appVersion = "v0.1.3"

func main() {
	initWindowsShellIdentity()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := newInspector(ctx, cfg)
	defer app.logs.Stop()

	mygo.App.WhenReady(func() {
		app.window = mygo.NewWindow(mygo.WindowOptions{
			Title: "Mihomo Inspector",
			Width: 1440, Height: 920,
			MinWidth: 1100, MinHeight: 720,
			Frameless: true, BackgroundColor: "#0c1218",
			Content: ui.View(app.view),
		})
	})
	if err := mygo.App.Run(); err != nil {
		log.Printf("run app: %v", err)
	}
}
