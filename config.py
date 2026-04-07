"""Configuration module for VaultSign.

Handles loading and saving settings from ~/.config/vaultsign/config.json.
Creates default configuration if none exists.
"""

import copy
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "vaultsign"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS = {
    "vault_addr": "https://vault.example.com:8200/",
    "vault_cli_path": "vault",
    "ssh_key_path": "~/.ssh/id_ed25519",
    "role": "",
    "ssh_signer_path": "ssh-client-signer",
    "show_tray": True,
    "autostart": True,
    "expiry_warn_minutes": 15,
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
    """Save configuration to disk with secure permissions (0700 dir, 0600 file)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)
    # Ensure permissions are tight even if file pre-existed with lax mode
    os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)


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


def export_profile(config: dict, name: str) -> dict:
    """Export a single profile as a portable dict."""
    profile = config.get("profiles", {}).get(name)
    if profile is None:
        return {}
    return {"profile_name": name, "profile_data": copy.deepcopy(profile)}


def import_profile(config: dict, data: dict) -> str | None:
    """Import a profile from exported data. Returns profile name, or None on error."""
    name = data.get("profile_name")
    profile_data = data.get("profile_data")
    if not name or not isinstance(profile_data, dict):
        return None
    # Merge with defaults to fill any missing keys
    merged = copy.deepcopy(DEFAULTS)
    merged.update(profile_data)
    # Deduplicate name if it already exists
    orig_name = name
    counter = 1
    while name in config.get("profiles", {}):
        counter += 1
        name = f"{orig_name} ({counter})"
    if "profiles" not in config:
        config["profiles"] = {}
    config["profiles"][name] = merged
    return name


# --- Session history ---

HISTORY_FILE = CONFIG_DIR / "history.json"
MAX_HISTORY = 100


def append_history(event: str, profile: str = "", detail: str = "") -> None:
    """Append an event to the session history log."""
    entries = load_history()
    entries.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "profile": profile,
        "detail": detail,
    })
    # Keep only the last MAX_HISTORY entries
    entries = entries[-MAX_HISTORY:]
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(HISTORY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        json.dump(entries, f, indent=2)


def load_history() -> list[dict]:
    """Load session history."""
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def clear_history() -> None:
    """Clear all session history."""
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
