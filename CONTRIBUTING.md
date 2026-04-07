# Contributing to VaultSign

Thanks for considering contributing to VaultSign! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/dem0n1337/vaultsign.git
cd vaultsign

# Run directly from repo (no install needed for development)
python3 vaultsign_gui.py

# Run with GTK Inspector for debugging
python3 vaultsign_gui.py --debug
```

### Dependencies

- Python 3.10+
- GTK 4, libadwaita
- python3-gobject (GObject Introspection)
- pytest (for tests)

On Fedora:
```bash
sudo dnf install python3-gobject gtk4 libadwaita
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

Tests cover: config management, certificate parsing, token redaction, version comparison, cancel logic.

## Code Style

- Follow PEP 8 (enforced by `ruff` in CI)
- Line length: 120 characters
- Use type hints where practical
- No external pip dependencies - stdlib + GObject only

## Making Changes

1. Fork the repo and create a feature branch
2. Make your changes
3. Run tests: `python3 -m pytest tests/ -v`
4. Check syntax: `python3 -c "import py_compile; py_compile.compile('your_file.py', doraise=True)"`
5. Open a PR with a clear description

## Commit Messages

Use conventional-ish style:
- `feat: add multi-key support`
- `fix: token renewal race condition`
- `refactor: extract fingerprint utility`
- `docs: update README installation`
- `test: add integration tests for auth flow`

## Project Structure

| File | Purpose |
|------|---------|
| `vaultsign_gui.py` | Main GTK4 application window and UI |
| `vault_backend.py` | All Vault/SSH subprocess operations |
| `config.py` | Configuration, profiles, session history |
| `cert_utils.py` | SSH certificate parsing |
| `tray.py` | Expiry monitoring and notifications |
| `tray_helper.py` | AppIndicator system tray |
| `updater.py` | GitHub release checker |
| `logger.py` | File logging with rotation |
| `tests/` | pytest unit tests |

## Important Notes

- **Thread safety**: GTK widgets must only be accessed from the main thread. Use `GLib.idle_add()` for UI updates from background threads. Read config via `_collect_config()` on the main thread before spawning workers.
- **No custom CSS providers**: They caused rendering issues on Fedora 43 with GTK 4.20. Use built-in libadwaita CSS classes only.
- **Security**: This is a credential management app. Never log tokens, always use `redact_tokens()`, write files with `0600` permissions.

## Questions?

Open an issue at [github.com/dem0n1337/vaultsign/issues](https://github.com/dem0n1337/vaultsign/issues).
