<div align="center">

<img src="icons/vaultsign-256.png" alt="VaultSign Logo" width="128">

# VaultSign

**Desktop GUI for HashiCorp Vault & OpenBao OIDC Authentication & SSH Key Signing**

![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Wails](https://img.shields.io/badge/Wails-React%20%2B%20Tailwind-DF0000?style=for-the-badge&logo=wails&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-3.0.0-blue?style=for-the-badge)

<br>

*Replace manual `vault login` + `vault write` + `ssh-add` workflows with a single click.*

[Features](#features) | [Installation](#installation) | [Quick Start](#quick-start) | [Configuration](#configuration) | [Contributing](CONTRIBUTING.md)

</div>

---

## What is VaultSign?

VaultSign is a Linux desktop application that streamlines SSH certificate management through HashiCorp Vault or OpenBao. Instead of juggling CLI commands, browser tabs, and terminal sessions, VaultSign handles the entire OIDC authentication and SSH key signing flow in a modern UI (Wails + React + Tailwind). It talks to Vault through the **native Go API** and to **ssh-agent over its socket directly** — no `vault`/`ssh-add` subprocesses — and ships as a single binary with no Python runtime.

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
- OIDC login (Google, Okta, etc.) with an in-app waiting screen
- Native Vault API — no `vault` CLI required
- Automatic SSH key signing
- Native ssh-agent integration (no `ssh-add`)
- Token reuse + renewal, certificate expiry monitoring

</td>
<td width="50%">

### Management
- Multiple configuration profiles
- Dynamic role fetching from Vault
- Session history with audit trail
- Profile export/import (JSON)
- Headless CLI (`vaultsign auth` / `status`)

</td>
</tr>
<tr>
<td>

### Security
- Token redaction in all logs
- Secure file permissions (0600)
- SSH key permission auto-fix
- Single binary, no Python runtime
- System browser for OIDC (Google-compliant)

</td>
<td>

### Desktop Integration
- Animated countdown ring for certificate TTL
- Desktop notifications (expiry warnings)
- System tray (StatusNotifierItem) with quick re-sign
- Light/Dark/System theme support
- XDG autostart on login

</td>
</tr>
</table>

## Build from source

VaultSign is a [Wails](https://wails.io) app: Go backend + React/Tailwind frontend.

```bash
# Prerequisites: Go 1.23+, Node 18+, and the Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

git clone https://github.com/dem0n1337/vaultsign.git
cd vaultsign
wails build -tags webkit2_41        # produces build/bin/vaultsign
```

> On Fedora pass `-tags webkit2_41` (only `webkit2gtk-4.1` is shipped). On
> distros with `webkit2gtk-4.0`, drop the tag.

For live development with hot-reload: `wails dev -tags webkit2_41`.

## Installation

### Quick Install (recommended)

```bash
git clone https://github.com/dem0n1337/vaultsign.git
cd vaultsign
sudo bash install.sh        # builds if needed, installs to /usr/local/bin
```

### Uninstall

```bash
sudo bash install.sh --uninstall
```

### RPM (Fedora / RHEL)

```bash
rpmbuild -ba packaging/vaultsign.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/vaultsign-*.rpm
```

### Flatpak

```bash
flatpak-builder --install --user build packaging/io.github.dem0n1337.vaultsign.yml
```

### Dependencies

**Build:** Go 1.23+, Node 18+, gcc, `webkit2gtk-4.1`/`gtk+-3.0` dev packages.

| Runtime dependency | Package (Fedora) | Package (Ubuntu) |
|-----------|-----------------|-----------------|
| WebKitGTK | `webkit2gtk4.1` | `libwebkit2gtk-4.1-0` |
| GTK 3 | `gtk3` | `libgtk-3-0` |

No Python, no `vault`/`ssh-add` binaries required at runtime.

## Quick Start

### 1. First Run

Launch VaultSign:
```bash
vaultsign
```

Open **Settings** and configure:
- Your Vault server address
- SSH key path, OIDC mount, and signer mount
- The role (type it, or hit refresh to fetch roles from Vault)

### 2. Authenticate

Click **Authenticate**. VaultSign will:

1. Verify prerequisites (SSH keys, permissions)
2. Probe Vault reachability (clear message if the VPN is down)
3. Reuse a valid token, or open your browser for OIDC login (in-app waiting screen)
4. Sign your SSH public key via the Vault API
5. Load the signed certificate into ssh-agent
6. Show certificate details with the animated countdown ring

### 3. Monitor

VaultSign runs in the background and will:
- Send desktop notifications when your certificate is expiring
- Offer quick re-sign and show/quit actions from the system tray
- Show remaining time via the countdown ring

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
      "ssh_key_path": "~/.ssh/id_ed25519",
      "oidc_mount": "oidc",
      "ssh_signer_path": "ssh-client-signer",
      "role": "engineer"
    },
    "staging": {
      "vault_addr": "https://vault-staging.company.com:8200/",
      "ssh_key_path": "~/.ssh/id_ed25519",
      "oidc_mount": "oidc",
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
| `ssh_key_path` | SSH private key path | `~/.ssh/id_ed25519` |
| `oidc_mount` | Vault OIDC auth mount | `oidc` |
| `ssh_signer_path` | Vault SSH signer mount | `ssh-client-signer` |
| `role` | OIDC role name | *(empty)* |
| `show_tray` | Enable tray icon | `true` |
| `autostart` | Start at login | `true` |
| `expiry_warn_minutes` | Warning threshold | `15` |

## CLI

VaultSign doubles as a headless CLI (handy for scripts/SSH config):

```bash
vaultsign            # Launch the GUI
vaultsign auth       # Run the full auth + sign flow headlessly
vaultsign status     # Print current token TTL and policies
vaultsign version    # Print version

# Flags for auth/status:
#   --profile NAME    use a specific config profile
#   --role NAME       override the role
```

## Troubleshooting

### "Vault CLI not found"
VaultSign needs `vault` or `bao` CLI in your PATH. Install via your package manager or let the setup wizard install it.

### SSH key permissions error
VaultSign auto-fixes SSH key permissions to `0600` if they're too open. If this keeps happening, check if another tool is changing permissions.

### "OIDC login timed out"
The browser-based login has a 5-minute timeout. Make sure your browser opened the Vault login page. Use **Cancel** on the in-app screen to abort sooner. Check firewall/proxy settings.

### "Vault unreachable" / `no such host`
Usually the corporate VPN is not connected. VaultSign probes reachability before launching the browser and reports this explicitly.

### Logs
Application logs are stored at `~/.local/share/vaultsign/vaultsign.log` with automatic rotation (1MB, 3 backups).

## Architecture

```
main.go                 Wails entrypoint + CLI router + single-instance lock
app.go                  Wails-bound methods (config, auth events, status, cert, notify)
cli.go                  Headless CLI (auth / status / version)
tray.go                 System-tray icon (StatusNotifierItem)
autostart.go            XDG autostart desktop entry
internal/config         JSON config: profiles, history (0600)
internal/vault          Native Vault API client: login, sign, token, roles, cert
internal/oidc           OIDC browser flow + localhost:8250 callback server
internal/sshagent       Native ssh-agent client (x/crypto/ssh/agent)
internal/logf           Rotating file logger with token redaction
frontend/               React + Tailwind UI (Vite), embedded into the binary
```

## License

[MIT](LICENSE) - Jakub Demovic & VaultSign Contributors

## Links

- [GitHub Repository](https://github.com/dem0n1337/vaultsign)
- [Report an Issue](https://github.com/dem0n1337/vaultsign/issues)
- [Man Page](vaultsign.1) - `man vaultsign`
