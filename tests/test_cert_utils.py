"""Tests for cert_utils module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cert_utils import _parse_keygen_output, _format_remaining, _parse_cert_time


SAMPLE_KEYGEN_OUTPUT = """\
/home/user/.ssh/id_ed25519-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:abc123
        Signing CA: ED25519 SHA256:def456 (using ssh-ed25519)
        Key ID: "user@example.com"
        Serial: 12345
        Valid: from 2026-04-07T10:00:00 to 2026-04-07T18:00:00
        Principals:
                user
                admin
        Critical Options: (none)
        Extensions:
                permit-pty
"""


class TestParseKeygenOutput:
    def test_parses_key_id(self):
        result = _parse_keygen_output(SAMPLE_KEYGEN_OUTPUT)
        assert result is not None
        assert result["key_id"] == "user@example.com"

    def test_parses_principals(self):
        result = _parse_keygen_output(SAMPLE_KEYGEN_OUTPUT)
        assert result is not None
        assert result["principals"] == ["user", "admin"]

    def test_parses_valid_times(self):
        result = _parse_keygen_output(SAMPLE_KEYGEN_OUTPUT)
        assert result is not None
        assert result["valid_from"].year == 2026
        assert result["valid_to"].hour == 18

    def test_returns_none_for_empty(self):
        result = _parse_keygen_output("")
        assert result is None

    def test_returns_none_for_no_valid_line(self):
        result = _parse_keygen_output("Key ID: \"test\"\nPrincipals:\n  user\n")
        assert result is None


class TestFormatRemaining:
    def test_expired(self):
        assert _format_remaining(0) == "Expired"
        assert _format_remaining(-10) == "Expired"

    def test_minutes_only(self):
        assert _format_remaining(300) == "5m"

    def test_hours_and_minutes(self):
        assert _format_remaining(7380) == "2h 3m"

    def test_days_and_hours(self):
        assert _format_remaining(90000) == "1d 1h"


class TestParseCertTime:
    def test_iso_without_tz(self):
        dt = _parse_cert_time("2026-04-07T10:00:00")
        assert dt.year == 2026
        assert dt.month == 4
        assert dt.hour == 10

    def test_iso_with_tz(self):
        dt = _parse_cert_time("2026-04-07T10:00:00+0000")
        assert dt.year == 2026

    def test_invalid_raises(self):
        try:
            _parse_cert_time("not-a-date")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
