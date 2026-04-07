"""Tests for updater module."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from updater import _version_newer, get_current_version, VERSION


class TestVersionNewer:
    def test_newer_patch(self):
        assert _version_newer("2.0.1", "2.0.0") is True

    def test_newer_minor(self):
        assert _version_newer("2.1.0", "2.0.0") is True

    def test_newer_major(self):
        assert _version_newer("3.0.0", "2.0.0") is True

    def test_same_version(self):
        assert _version_newer("2.0.0", "2.0.0") is False

    def test_older_version(self):
        assert _version_newer("1.9.9", "2.0.0") is False

    def test_invalid_version(self):
        assert _version_newer("abc", "2.0.0") is False

    def test_both_invalid(self):
        assert _version_newer("abc", "def") is False


class TestGetCurrentVersion:
    def test_returns_version_string(self):
        v = get_current_version()
        assert v == VERSION
        parts = v.split(".")
        assert len(parts) == 3
