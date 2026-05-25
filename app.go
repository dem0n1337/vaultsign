package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/dem0n1337/vaultsign/internal/config"
	"github.com/dem0n1337/vaultsign/internal/logf"
	"github.com/dem0n1337/vaultsign/internal/vault"
)

// App is the Wails-bound application backend. Its exported methods are callable
// from the React frontend; it reuses the internal config/vault/oidc/sshagent
// packages unchanged.
type App struct {
	ctx context.Context
	log *logf.Logger

	mu         sync.Mutex
	authCancel context.CancelFunc

	notified bool // whether we've already warned about the current session's expiry
}

// NewApp constructs the application backend.
func NewApp() *App {
	l, _ := logf.New()
	return &App{log: l}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.expiryWatcher()

	cfg := config.Load()
	if cfg.Active().ShowTray {
		a.startTray()
	}
	_ = syncAutostart(cfg.Active().Autostart)
}

// expiryWatcher periodically checks token TTL and fires a desktop notification
// once when it drops below the configured warning threshold.
func (a *App) expiryWatcher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cfg := config.Load()
		profile := cfg.Active()
		be, err := vault.New(profile)
		if err != nil {
			continue
		}
		info := be.TokenStatus(context.Background())
		if info == nil {
			a.notified = false
			continue
		}
		warn := time.Duration(profile.ExpiryWarnMins) * time.Minute
		if warn <= 0 {
			warn = 15 * time.Minute
		}
		if info.TTL > warn {
			a.notified = false // healthy again (e.g. after renew/re-auth)
			continue
		}
		if info.TTL > 0 && !a.notified {
			a.notified = true
			_ = beeep.Notify("VaultSign", fmt.Sprintf("SSH certificate expires in %s — re-sign soon.", fmtDuration(info.TTL)), "")
			runtime.EventsEmit(a.ctx, "session:expiring", info.TTL.Seconds())
		}
	}
}

// Version returns the app version string.
func (a *App) Version() string { return version }

// GetConfig returns the full on-disk configuration.
func (a *App) GetConfig() *config.Config { return config.Load() }

// SaveConfig persists the configuration sent from the frontend.
func (a *App) SaveConfig(cfg config.Config) error { return cfg.Save() }

// Status is the token/session summary sent to the frontend.
type Status struct {
	Valid              bool     `json:"valid"`
	DisplayName        string   `json:"displayName"`
	TTLSeconds         float64  `json:"ttlSeconds"`
	CreationTTLSeconds float64  `json:"creationTtlSeconds"`
	TTLLabel           string   `json:"ttlLabel"`
	Policies           []string `json:"policies"`
	Renewable          bool     `json:"renewable"`
}

// TokenStatus returns the current Vault token status for the active profile.
func (a *App) TokenStatus() Status {
	be, err := vault.New(config.Load().Active())
	if err != nil {
		return Status{}
	}
	info := be.TokenStatus(context.Background())
	if info == nil {
		return Status{}
	}
	creation := info.CreationTTL.Seconds()
	if creation <= 0 {
		creation = info.TTL.Seconds()
	}
	return Status{
		Valid:              true,
		DisplayName:        info.DisplayName,
		TTLSeconds:         info.TTL.Seconds(),
		CreationTTLSeconds: creation,
		TTLLabel:           fmtDuration(info.TTL),
		Policies:           info.Policies,
		Renewable:          info.Renewable,
	}
}

// CertDetails is the signed certificate summary sent to the frontend.
type CertDetails struct {
	Valid       bool     `json:"valid"`
	KeyID       string   `json:"keyId"`
	Serial      string   `json:"serial"`
	Principals  []string `json:"principals"`
	ValidBefore string   `json:"validBefore"`
	Extensions  []string `json:"extensions"`
}

// CertDetails returns details of the locally signed SSH certificate.
func (a *App) CertDetails() CertDetails {
	be, err := vault.New(config.Load().Active())
	if err != nil {
		return CertDetails{}
	}
	c := be.CertInfo()
	if !c.Valid {
		return CertDetails{}
	}
	vb := ""
	if !c.ValidBefore.IsZero() {
		vb = c.ValidBefore.Format(time.RFC3339)
	}
	return CertDetails{
		Valid:       true,
		KeyID:       c.KeyID,
		Serial:      fmt.Sprintf("%d", c.Serial),
		Principals:  c.Principals,
		ValidBefore: vb,
		Extensions:  c.Extensions,
	}
}

// ListRoles returns the OIDC roles configured in Vault for the active profile.
func (a *App) ListRoles() []string {
	be, err := vault.New(config.Load().Active())
	if err != nil {
		return nil
	}
	roles, err := be.ListRoles(context.Background())
	if err != nil {
		return nil
	}
	return roles
}

// Result is a generic ok/message response.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// RenewToken renews the active profile's Vault token.
func (a *App) RenewToken() Result {
	be, err := vault.New(config.Load().Active())
	if err != nil {
		return Result{false, err.Error()}
	}
	ok, msg := be.RenewToken(context.Background())
	return Result{ok, msg}
}

// Authenticate runs the full OIDC + sign + agent flow, emitting "auth:step",
// "auth:url" and "auth:done" events to the frontend as it progresses.
func (a *App) Authenticate(force bool) Result {
	cfg := config.Load()
	profile := cfg.Active()

	be, err := vault.New(profile)
	if err != nil {
		return Result{false, err.Error()}
	}
	be.ForceLogin = force
	be.LaunchOIDC = func(url string) {
		runtime.EventsEmit(a.ctx, "auth:url", url)
	}

	cb := func(step string, ok bool, detail string) {
		runtime.EventsEmit(a.ctx, "auth:step", map[string]any{
			"step": step, "ok": ok, "detail": detail,
		})
		if a.log != nil {
			a.log.Step(step, ok, detail)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.authCancel = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.authCancel = nil
		a.mu.Unlock()
		cancel()
	}()

	ok, out := be.RunFull(ctx, cb)
	if ok {
		_ = config.AppendHistory("auth_success", profile.Role, "", "")
	} else {
		_ = config.AppendHistory("auth_failed", profile.Role, "", out)
	}
	runtime.EventsEmit(a.ctx, "auth:done", map[string]any{"ok": ok, "message": out})
	return Result{ok, out}
}

// ExportActiveProfile writes the active profile to a user-chosen JSON file.
func (a *App) ExportActiveProfile() Result {
	cfg := config.Load()
	name := cfg.ActiveProfile
	p, ok := cfg.Profiles[name]
	if !ok {
		return Result{false, "no active profile"}
	}
	data, err := json.MarshalIndent(map[string]any{"profile_name": name, "profile_data": p}, "", "  ")
	if err != nil {
		return Result{false, err.Error()}
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: name + ".vaultsign.json",
		Title:           "Export profile",
	})
	if err != nil || path == "" {
		return Result{false, "cancelled"}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return Result{false, err.Error()}
	}
	return Result{true, "Exported to " + path}
}

// ImportProfile reads a profile from a user-chosen JSON file and adds it.
func (a *App) ImportProfile() Result {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{Title: "Import profile"})
	if err != nil || path == "" {
		return Result{false, "cancelled"}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{false, err.Error()}
	}
	var imp struct {
		ProfileName string         `json:"profile_name"`
		ProfileData config.Profile `json:"profile_data"`
	}
	if err := json.Unmarshal(raw, &imp); err != nil || imp.ProfileName == "" {
		return Result{false, "invalid profile file"}
	}
	cfg := config.Load()
	name := imp.ProfileName
	for i := 2; ; i++ {
		if _, exists := cfg.Profiles[name]; !exists {
			break
		}
		name = fmt.Sprintf("%s (%d)", imp.ProfileName, i)
	}
	cfg.Profiles[name] = imp.ProfileData
	cfg.ActiveProfile = name
	if err := cfg.Save(); err != nil {
		return Result{false, err.Error()}
	}
	return Result{true, "Imported profile " + name}
}

// CancelAuth aborts an in-flight authentication (closes the OIDC callback wait).
func (a *App) CancelAuth() {
	a.mu.Lock()
	cancel := a.authCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func fmtDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
