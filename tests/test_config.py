"""Tests for config module."""

import copy
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config


class TestLoadConfig:
    def test_returns_defaults_when_no_file(self, tmp_path):
        with mock.patch.object(config, "CONFIG_FILE", tmp_path / "nonexistent.json"):
            result = config.load_config()
        assert result["active_profile"] == "default"
        assert "default" in result["profiles"]
        assert result["profiles"]["default"]["vault_addr"] == config.DEFAULTS["vault_addr"]

    def test_migrates_flat_format(self, tmp_path):
        flat_config = {"vault_addr": "https://vault.test:8200/", "role": "admin"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(flat_config))
        with mock.patch.object(config, "CONFIG_FILE", config_file):
            result = config.load_config()
        assert result["profiles"]["default"]["vault_addr"] == "https://vault.test:8200/"
        assert result["profiles"]["default"]["role"] == "admin"

    def test_loads_profile_format(self, tmp_path):
        profile_config = {
            "active_profile": "prod",
            "profiles": {"prod": {"vault_addr": "https://prod.vault:8200/"}},
            "theme": "dark",
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(profile_config))
        with mock.patch.object(config, "CONFIG_FILE", config_file):
            result = config.load_config()
        assert result["active_profile"] == "prod"
        assert result["theme"] == "dark"

    def test_handles_corrupt_json(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text("{invalid json")
        with mock.patch.object(config, "CONFIG_FILE", config_file):
            result = config.load_config()
        assert result["active_profile"] == "default"


class TestSaveConfig:
    def test_saves_with_secure_permissions(self, tmp_path):
        config_dir = tmp_path / "vaultsign"
        config_file = config_dir / "config.json"
        with mock.patch.object(config, "CONFIG_DIR", config_dir), \
             mock.patch.object(config, "CONFIG_FILE", config_file):
            data = {"active_profile": "default", "profiles": {}, "theme": "system"}
            config.save_config(data)
        assert config_file.exists()
        file_stat = config_file.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600


class TestProfileOperations:
    def _make_config(self):
        return {
            "active_profile": "default",
            "profiles": {
                "default": copy.deepcopy(config.DEFAULTS),
                "staging": copy.deepcopy(config.DEFAULTS),
            },
            "theme": "system",
        }

    def test_get_active_profile(self):
        c = self._make_config()
        profile = config.get_active_profile(c)
        assert profile["vault_addr"] == config.DEFAULTS["vault_addr"]

    def test_set_active_profile(self):
        c = self._make_config()
        profile = config.set_active_profile(c, "staging")
        assert c["active_profile"] == "staging"

    def test_delete_profile(self):
        c = self._make_config()
        assert config.delete_profile(c, "staging") is True
        assert "staging" not in c["profiles"]

    def test_cannot_delete_last_profile(self):
        c = {"active_profile": "default", "profiles": {"default": {}}}
        assert config.delete_profile(c, "default") is False

    def test_delete_active_switches(self):
        c = self._make_config()
        c["active_profile"] = "staging"
        config.delete_profile(c, "staging")
        assert c["active_profile"] == "default"

    def test_list_profiles(self):
        c = self._make_config()
        names = config.list_profiles(c)
        assert "default" in names
        assert "staging" in names
