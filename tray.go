package main

import (
	_ "embed"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed icons/vaultsign-32.png
var trayIcon []byte

// startTray runs a system-tray icon (DBus StatusNotifierItem on Linux, so it
// does not conflict with the Wails GTK loop). It offers quick re-sign, show,
// and quit actions.
func (a *App) startTray() {
	onReady := func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle("")
		systray.SetTooltip("VaultSign")

		show := systray.AddMenuItem("Show VaultSign", "Open the window")
		resign := systray.AddMenuItem("Re-sign SSH key", "Authenticate and sign")
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Exit VaultSign")

		show.Click(func() { runtime.WindowShow(a.ctx) })
		resign.Click(func() { go a.Authenticate(false) })
		quit.Click(func() {
			systray.Quit()
			runtime.Quit(a.ctx)
		})
		systray.SetOnClick(func(menu systray.IMenu) { runtime.WindowShow(a.ctx) })
	}
	go systray.Run(onReady, func() {})
}
