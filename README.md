<div align="center">

<img src="icons/vaultsign-256.png" alt="VaultSign Logo" width="128">

# VaultSign

**Desktop GUI for HashiCorp Vault & OpenBao OIDC Authentication & SSH Key Signing**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![GTK4](https://img.shields.io/badge/GTK4-libadwaita-7F39FB?style=for-the-badge&logo=gtk&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![CI](https://img.shields.io/github/actions/workflow/status/dem0n1337/vaultsign/ci.yml?style=for-the-badge&logo=github-actions&label=CI)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)

<br>

*Replace manual `vault login` + `vault write` + `ssh-add` workflows with a single click.*

[Features](#features) | [Installation](#installation) | [Quick Start](#quick-start) | [Configuration](#configuration) | [Contributing](CONTRIBUTING.md)

</div>

---

## What is VaultSign?

VaultSign is a native Linux desktop application that streamlines SSH certificate management through HashiCorp Vault or OpenBao. Instead of juggling CLI commands, browser tabs, and terminal sessions, VaultSign handles the entire OIDC authentication and SSH key signing flow in a clean GTK4 interface.

```
Without VaultSign:                    With VaultSign:
                                      
  vault login -method=oidc             Click "Authenticate"
  vault write ssh-client-signer/...    Done.
  ssh-add ~/.ssh/id_ed25519            
  ssh-keygen -L -f ...                 
```

## Features

<table>
<tr>
<td width="50%">

### Authentication
- OIDC login via browser (Google, Okta, etc.)
- Automatic SSH key signing
- SSH agent integration
- Token auto-renewal
- Certificate expiry monitoring

</td>
<td width="50%">

### Management
- Multiple configuration profiles
- Dynamic role fetching from Vault
- Session history with audit trail
- Profile export/import (JSON)
- CLI auto-detection (vault / bao)

</td>
</tr>
<tr>
<td>

### Security
- Token redaction in all logs
- Secure file permissions (0600)
- SSH key permission auto-fix
- Core dump disabled
- No external Python dependencies

</td>
<td>

### Desktop Integration
- Animated countdown ring for certificate TTL
- Desktop notifications (expiry warnings)
- System tray with AppIndicator
- Light/Dark/System theme support
- Keyboard shortcuts (Ctrl+Enter, Ctrl+S, Esc)

</td>
</tr>
</table>

## Screenshots

> *Screenshots coming soon. Run `vaultsign --debug` to see the app with GTK Inspector.*

## Installation

### Quick Install (recommended)

```bash
git clone https://github.com/dem0n1337/vaultsign.git
cd vaultsign
sudo bash install.sh
```

The installer will ask where to install (default: `/opt/vaultsign`).

For non-interactive install:
```bash
sudo bash install.sh --path /opt/vaultsign
```

### Uninstall

```bash
sudo bash install.sh --uninstall
```

### RPM (Fedora / RHEL)

```bash
rpmbuild -ba packaging/vaultsign.spec
sudo dnf install ~/rpmbuild/RPMS/noarch/vaultsign-*.rpm
```

### Flatpak

```bash
flatpak-builder --install --user build packaging/io.github.dem0n1337.vaultsign.yml
```

### Dependencies

| Dependency | Package (Fedora) | Package (Ubuntu) |
|-----------|-----------------|-----------------|
| Python 3.10+ | `python3` | `python3` |
| GTK 4 | `gtk4` | `libgtk-4-dev` |
| libadwaita | `libadwaita` | `libadwaita-1-dev` |
| GObject Introspection | `python3-gobject` | `python3-gi` |
| Vault or OpenBao CLI | `vault` or `openbao` | `vault` or `openbao` |

## Quick Start

### 1. First Run

Launch VaultSign:
```bash
vaultsign
```

The setup wizard will:
- Detect if `vault` or `bao` CLI is installed (offers to install if missing)
- Ask for your Vault server address
- Configure SSH key path and default role

### 2. Authenticate

Click **Authenticate** or press `Ctrl+Enter`. VaultSign will:

1. Verify prerequisites (CLI, SSH keys, permissions)
2. Open your browser for OIDC login
3. Sign your SSH public key via Vault
4. Add the signed certificate to ssh-agent
5. Show certificate details with animated countdown

### 3. Monitor

VaultSign runs in the background and will:
- Auto-renew tokens before they expire
- Send desktop notifications when your certificate is expiring
- Show remaining time via system tray icon

## Configuration

Config is stored at `~/.config/vaultsign/config.json`.

### Profiles

VaultSign supports multiple profiles for different Vault servers or roles:

```json
{
  "active_profile": "production",
  "profiles": {
    "production": {
      "vault_addr": "https://vault.company.com:8200/",
      "vault_cli_path": "vault",
      "ssh_key_path": "~/.ssh/id_ed25519",
      "ssh_signer_path": "ssh-client-signer",
      "role": "engineer"
    },
    "staging": {
      "vault_addr": "https://vault-staging.company.com:8200/",
      "vault_cli_path": "vault",
      "ssh_key_path": "~/.ssh/id_ed25519",
      "ssh_signer_path": "ssh-client-signer",
      "role": "admin"
    }
  },
  "theme": "system"
}
```

### Key Settings

| Setting | Description | Default |
|---------|------------|---------|
| `vault_addr` | Vault/OpenBao server URL | `https://vault.example.com:8200/` |
| `vault_cli_path` | Path to vault/bao binary | `vault` |
| `ssh_key_path` | SSH private key path | `~/.ssh/id_ed25519` |
| `ssh_signer_path` | Vault SSH signer mount | `ssh-client-signer` |
| `role` | OIDC role name | *(empty)* |
| `show_tray` | Enable tray icon | `true` |
| `autostart` | Start at login | `true` |
| `expiry_warn_minutes` | Warning threshold | `15` |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Authenticate |
| `Ctrl+S` | Save settings |
| `Ctrl+L` | Copy log to clipboard |
| `Escape` | Cancel authentication |

## CLI Flags

```bash
vaultsign                # Normal launch
vaultsign --minimize     # Start minimized to tray
vaultsign --debug        # Enable GTK Inspector + verbose logging
```

## Troubleshooting

### "Vault CLI not found"
VaultSign needs `vault` or `bao` CLI in your PATH. Install via your package manager or let the setup wizard install it.

### SSH key permissions error
VaultSign auto-fixes SSH key permissions to `0600` if they're too open. If this keeps happening, check if another tool is changing permissions.

### "OIDC login timed out"
The browser-based login has a 5-minute timeout. Make sure your browser opened the Vault login page. Check firewall/proxy settings.

### Text not visible (Fedora/GNOME)
If text appears invisible, check for custom GTK4 CSS overrides:
```bash
cat ~/.config/gtk-4.0/gtk.css
```
Remove or fix any `color: #333333` rules that conflict with dark theme.

### Logs
Application logs are stored at `~/.local/share/vaultsign/vaultsign.log` with automatic rotation (1MB, 3 backups).

## Architecture

```
vaultsign_gui.py      GTK4/libadwaita UI (NavigationView, Cairo ring)
vault_backend.py      Subprocess wrapper for vault/bao CLI operations
config.py             JSON config with profiles, migration, history
cert_utils.py         SSH certificate parsing (ssh-keygen -L)
tray.py               Certificate expiry monitor + desktop notifications
tray_helper.py        AppIndicator3 system tray icon
updater.py            GitHub release checker
logger.py             Rotating file logger with token redaction
```

## License

[MIT](LICENSE) - Jakub Demovic & VaultSign Contributors

## Links

- [GitHub Repository](https://github.com/dem0n1337/vaultsign)
- [Report an Issue](https://github.com/dem0n1337/vaultsign/issues)
- [Man Page](vaultsign.1) - `man vaultsign`
