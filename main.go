package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

const version = "3.0.0"

func main() {
	// Headless CLI paths share the same backend (see cli.go).
	if len(os.Args) > 1 {
		runCLI(os.Args[1:])
		return
	}

	app := NewApp()
	err := wails.Run(&options.App{
		Title:     "VaultSign",
		Width:     440,
		Height:    760,
		MinWidth:  400,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 18, G: 18, B: 24, A: 1},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "io.github.dem0n1337.vaultsign",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				runtime.WindowShow(app.ctx)
			},
		},
		Linux: &linux.Options{
			ProgramName: "vaultsign",
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
