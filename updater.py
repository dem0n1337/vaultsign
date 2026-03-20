"""Auto-update checker for VaultSign."""

import json
import urllib.request

VERSION = "2.0.0"
GITHUB_REPO = "dem0n1337/vaultsign"
RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def get_current_version() -> str:
    return VERSION


def check_for_update() -> dict | None:
    """Check GitHub for a newer release.

    Returns dict with: version, url, body (release notes)
    Or None if up-to-date or check fails.
    """
    try:
        req = urllib.request.Request(RELEASES_URL, headers={"User-Agent": "VaultSign"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        latest = data.get("tag_name", "").lstrip("v")
        if not latest:
            return None

        if _version_newer(latest, VERSION):
            return {
                "version": latest,
                "url": data.get("html_url", ""),
                "body": data.get("body", ""),
            }
        return None
    except Exception:
        return None


def _version_newer(latest: str, current: str) -> bool:
    """Compare semver strings."""
    try:
        l_parts = [int(x) for x in latest.split(".")]
        c_parts = [int(x) for x in current.split(".")]
        return l_parts > c_parts
    except ValueError:
        return False
