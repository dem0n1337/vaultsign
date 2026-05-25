// Package config handles VaultSign profiles, settings and session history.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Profile holds the per-profile Vault/SSH settings.
type Profile struct {
	VaultAddr      string `json:"vault_addr"`
	SSHKeyPath     string `json:"ssh_key_path"`
	Role           string `json:"role"`
	SSHSignerPath  string `json:"ssh_signer_path"`
	OIDCMount      string `json:"oidc_mount"`
	ShowTray       bool   `json:"show_tray"`
	Autostart      bool   `json:"autostart"`
	ExpiryWarnMins int    `json:"expiry_warn_minutes"`
}

// Defaults returns a fresh profile with default values.
func Defaults() Profile {
	return Profile{
		VaultAddr:      "https://vault.example.com:8200/",
		SSHKeyPath:     "~/.ssh/id_ed25519",
		Role:           "",
		SSHSignerPath:  "ssh-client-signer",
		OIDCMount:      "oidc",
		ShowTray:       true,
		Autostart:      true,
		ExpiryWarnMins: 15,
	}
}

// Config is the full on-disk configuration.
type Config struct {
	ActiveProfile string             `json:"active_profile"`
	Profiles      map[string]Profile `json:"profiles"`
	Theme         string             `json:"theme"`
}

func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "vaultsign"), nil
}

func configPath() (string, error) {
	d, err := dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// Load reads config from disk, returning defaults if absent or invalid.
func Load() *Config {
	c := &Config{
		ActiveProfile: "default",
		Profiles:      map[string]Profile{"default": Defaults()},
		Theme:         "system",
	}
	path, err := configPath()
	if err != nil {
		return c
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var stored Config
	if err := json.Unmarshal(data, &stored); err != nil || len(stored.Profiles) == 0 {
		return c
	}
	if stored.ActiveProfile != "" {
		c.ActiveProfile = stored.ActiveProfile
	}
	if stored.Theme != "" {
		c.Theme = stored.Theme
	}
	c.Profiles = stored.Profiles
	return c
}

// Save writes config to disk with 0700 dir / 0600 file permissions.
func (c *Config) Save() error {
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	path := filepath.Join(d, "config.json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Active returns the active profile, or defaults if missing.
func (c *Config) Active() Profile {
	if p, ok := c.Profiles[c.ActiveProfile]; ok {
		return p
	}
	return Defaults()
}

// --- session history ---

// Event is a single auth attempt record.
type Event struct {
	Time    string `json:"time"`
	Event   string `json:"event"`
	Profile string `json:"profile"`
	Step    string `json:"step,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

const maxHistory = 100

func historyPath() (string, error) {
	d, err := dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "history.json"), nil
}

// LoadHistory returns the session history (empty on error).
func LoadHistory() []Event {
	path, err := historyPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var events []Event
	if json.Unmarshal(data, &events) != nil {
		return nil
	}
	return events
}

// AppendHistory records an event, capping the log at maxHistory entries.
func AppendHistory(event, profile, step, detail string) error {
	events := LoadHistory()
	events = append(events, Event{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Event:   event,
		Profile: profile,
		Step:    step,
		Detail:  detail,
	})
	if len(events) > maxHistory {
		events = events[len(events)-maxHistory:]
	}
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	path := filepath.Join(d, "history.json")
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
