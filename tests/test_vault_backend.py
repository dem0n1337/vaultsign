"""Tests for vault_backend module."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vault_backend import redact_tokens, is_cancelled, reset_cancel, request_cancel


class TestRedactTokens:
    def test_redacts_hvs_token(self):
        text = "token=hvs.CAESIGh2cy5hYmMxMjM0NTY3ODkw"
        result = redact_tokens(text)
        assert "hvs.***REDACTED***" in result
        assert "CAESIGh2cy" not in result

    def test_redacts_hvb_token(self):
        text = "batch token: hvb.AAAAAQJhYmMxMjM0"
        result = redact_tokens(text)
        assert "hvb.***REDACTED***" in result

    def test_redacts_hvr_token(self):
        text = "recovery: hvr.someLongTokenValue123"
        result = redact_tokens(text)
        assert "hvr.***REDACTED***" in result

    def test_redacts_legacy_s_token(self):
        text = "token: s.abcdefghijklmnopqrstuvwx"
        result = redact_tokens(text)
        assert "s.***REDACTED***" in result

    def test_ignores_short_s_dot(self):
        # Short s. patterns should not be redacted (not tokens)
        text = "e.g. this is fine"
        result = redact_tokens(text)
        assert result == text

    def test_preserves_normal_text(self):
        text = "Authentication successful, no tokens here"
        assert redact_tokens(text) == text

    def test_redacts_multiple_tokens(self):
        text = "first: hvs.abc123def456 second: hvb.xyz789"
        result = redact_tokens(text)
        assert "abc123" not in result
        assert "xyz789" not in result

    def test_empty_string(self):
        assert redact_tokens("") == ""


class TestCancelLogic:
    def test_initial_state(self):
        reset_cancel()
        assert is_cancelled() is False

    def test_request_cancel(self):
        reset_cancel()
        request_cancel()
        assert is_cancelled() is True

    def test_reset_cancel(self):
        request_cancel()
        reset_cancel()
        assert is_cancelled() is False
