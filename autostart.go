package main

import (
	"os"
	"path/filepath"
)

// syncAutostart creates or removes the XDG autostart desktop entry so VaultSign
// launches on login when enabled in the active profile.
func syncAutostart(enabled bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".config", "autostart")
	path := filepath.Join(dir, "vaultsign.desktop")

	if !enabled {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "vaultsign"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entry := "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=VaultSign\n" +
		"Comment=Vault OIDC authentication & SSH key signing\n" +
		"Exec=" + exe + "\n" +
		"Icon=vaultsign\n" +
		"Terminal=false\n" +
		"X-GNOME-Autostart-enabled=true\n"
	return os.WriteFile(path, []byte(entry), 0o644)
}
