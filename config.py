"""Configuration module for VaultSign.

Handles loading and saving settings from ~/.config/vaultsign/config.json.
Creates default configuration if none exists.
"""

import copy
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
    "cert_ttl": "",  # empty = server default
    "show_tray": True,
    "expiry_warn_minutes": 30,
}


def load_config() -> dict:
    """Load config, migrating from flat format to profiles if needed."""
    config = {"active_profile": "default", "profiles": {"default": copy.deepcopy(DEFAULTS)}, "theme": "system"}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                stored = json.load(f)
            if "vault_addr" in stored:
                # Migration from flat format
                profile_data = {k: stored[k] for k in DEFAULTS if k in stored}
                config["profiles"]["default"] = {**copy.deepcopy(DEFAULTS), **profile_data}
                config["theme"] = stored.get("theme", "system")
            else:
                config.update(stored)
                for name, profile in config.get("profiles", {}).items():
                    merged = copy.deepcopy(DEFAULTS)
                    merged.update(profile)
                    config["profiles"][name] = merged
        except (json.JSONDecodeError, OSError):
            pass
    return config


def save_config(config: dict) -> None:
    """Save configuration to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_active_profile(config: dict) -> dict:
    """Get the active profile's settings."""
    name = config.get("active_profile", "default")
    return config.get("profiles", {}).get(name, copy.deepcopy(DEFAULTS))


def set_active_profile(config: dict, name: str) -> dict:
    """Switch active profile. Returns the profile settings."""
    config["active_profile"] = name
    return get_active_profile(config)


def save_profile(config: dict, name: str, profile_data: dict) -> None:
    """Save a profile's settings into the config."""
    if "profiles" not in config:
        config["profiles"] = {}
    config["profiles"][name] = profile_data


def delete_profile(config: dict, name: str) -> bool:
    """Delete a profile. Cannot delete the last profile."""
    profiles = config.get("profiles", {})
    if len(profiles) <= 1:
        return False
    if name in profiles:
        del profiles[name]
        if config.get("active_profile") == name:
            config["active_profile"] = next(iter(profiles))
        return True
    return False


def list_profiles(config: dict) -> list[str]:
    """List all profile names."""
    return list(config.get("profiles", {}).keys())
