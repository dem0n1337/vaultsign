"""Certificate parsing utilities for VaultSign."""

import os
import subprocess
from datetime import datetime, timezone


def parse_cert_expiry(cert_path: str) -> dict | None:
    """Parse SSH certificate and return expiry info.

    Returns dict with keys:
        valid_from: datetime
        valid_to: datetime
        remaining_seconds: int
        remaining_human: str (e.g. "7h 23m")
        is_expired: bool
        principals: list[str]
        key_id: str
    Or None if cert doesn't exist or can't be parsed.
    """
    cert_path = os.path.expanduser(cert_path)
    if not os.path.isfile(cert_path):
        return None

    try:
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", cert_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None
        return _parse_keygen_output(result.stdout)
    except Exception:
        return None


def _parse_keygen_output(output: str) -> dict | None:
    """Parse ssh-keygen -L output into structured data."""
    info = {"principals": []}
    in_principals = False

    for line in output.splitlines():
        stripped = line.strip()

        if stripped.startswith("Valid:"):
            parts = stripped.split()
            try:
                from_str = parts[2]
                to_str = parts[4]
                info["valid_from"] = _parse_cert_time(from_str)
                info["valid_to"] = _parse_cert_time(to_str)
                now = datetime.now(timezone.utc)
                remaining = (info["valid_to"] - now).total_seconds()
                info["remaining_seconds"] = max(0, int(remaining))
                info["is_expired"] = remaining <= 0
                info["remaining_human"] = _format_remaining(info["remaining_seconds"])
            except (IndexError, ValueError):
                pass
            in_principals = False
        elif stripped.startswith("Key ID:"):
            info["key_id"] = stripped.split('"')[1] if '"' in stripped else stripped[7:].strip()
            in_principals = False
        elif stripped.startswith("Principals:"):
            in_principals = True
        elif in_principals and stripped:
            if stripped.startswith("Critical") or stripped.startswith("Extensions"):
                in_principals = False
            else:
                info["principals"].append(stripped)

    if "valid_to" not in info:
        return None
    return info


def _parse_cert_time(time_str: str) -> datetime:
    """Parse certificate timestamp into datetime."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(time_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"Cannot parse time: {time_str}")


def _format_remaining(seconds: int) -> str:
    """Format remaining seconds as human-readable string."""
    if seconds <= 0:
        return "Expired"
    hours, remainder = divmod(seconds, 3600)
    minutes = remainder // 60
    if hours > 24:
        days = hours // 24
        hours = hours % 24
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
