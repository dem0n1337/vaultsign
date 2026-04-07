# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

If you find a security vulnerability in VaultSign, please **do not** open a public issue.

Instead, open a [private security advisory](https://github.com/dem0n1337/vaultsign/security/advisories/new) on GitHub.

You should receive a response within 48 hours. Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Design

VaultSign handles sensitive data (Vault tokens, SSH keys, server addresses). Here's how we protect it:

### Token Protection
- All Vault tokens (`hvs.*`, `hvb.*`, `hvr.*`, `s.*`) are automatically redacted from logs and UI
- Clipboard auto-clears after 30 seconds when copying sensitive data
- Core dumps are disabled at startup (`RLIMIT_CORE = 0`)

### File Permissions
- Config file (`~/.config/vaultsign/config.json`): `0600`
- History file (`~/.config/vaultsign/history.json`): `0600`
- Log file (`~/.local/share/vaultsign/vaultsign.log`): `0600`
- Signed certificates: `0600`
- SSH key permissions auto-fixed to `0600` if too open

### Process Isolation
- All vault/bao CLI calls use `subprocess.Popen` with argument lists (no shell injection)
- Each subprocess gets an isolated environment with only `VAULT_ADDR` set
- Subprocess timeouts: 5 min (OIDC login), 2 min (key signing), 10 sec (status checks)

### No External Dependencies
VaultSign uses only Python standard library + system GTK4/libadwaita. No pip packages, no supply chain risk from PyPI.

## Known Limitations

- Config file contains `vault_addr` and `ssh_key_path` in plaintext (not encrypted)
- GNOME Keyring (gcr-ssh-agent) prevents programmatic SSH key removal from agent
- Update checker contacts GitHub API over HTTPS (no certificate pinning)
