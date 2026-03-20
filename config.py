"""Configuration module for VaultSign.

Handles loading and saving settings from ~/.config/vaultsign/config.json.
Creates default configuration if none exists.
"""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "vaultsign"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS = {
    "vault_addr": "https://vault.example.com:8200/",
    "vault_cli_path": "vault",
    "ssh_key_path": "~/.ssh/id_ed25519",
    "role": "",
    "saved_roles": [],
}


def load_config() -> dict:
    """Load configuration from disk, returning defaults for any missing keys."""
    config = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                stored = json.load(f)
            config.update(stored)
        except (json.JSONDecodeError, OSError):
            pass
    return config


def save_config(config: dict) -> None:
    """Save configuration to disk, creating the directory if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
