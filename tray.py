"""Certificate expiry notification and system tray support for VaultSign."""

import os
import subprocess

import gi
from gi.repository import Gio, GLib


class ExpiryMonitor:
    """Monitors certificate expiry and sends desktop notifications."""

    def __init__(self, app, config_fn, get_cert_info_fn):
        self.app = app
        self._config_fn = config_fn  # callable returning current profile dict
        self.get_cert_info = get_cert_info_fn
        self._timer_id = None
        self._warned = False

    def start(self):
        """Start monitoring. Checks every 5 minutes."""
        self._check()
        self._timer_id = GLib.timeout_add_seconds(300, self._check)

    def stop(self):
        if self._timer_id is not None:
            GLib.source_remove(self._timer_id)
            self._timer_id = None

    def _check(self) -> bool:
        info = self.get_cert_info()
        if info is None:
            return True

        config = self._config_fn()
        warn_minutes = config.get("expiry_warn_minutes", 15)
        remaining_minutes = info["remaining_seconds"] // 60

        if info["is_expired"]:
            self._send_notification("Certificate Expired",
                "Your SSH certificate has expired. Please re-authenticate.",
                "dialog-error")
            self._warned = True
        elif remaining_minutes <= warn_minutes and not self._warned:
            self._send_notification("Certificate Expiring Soon",
                f"Your SSH certificate expires in {info['remaining_human']}.",
                "dialog-warning")
            self._warned = True
        elif remaining_minutes > warn_minutes:
            self._warned = False

        return True

    def _send_notification(self, title, body, icon):
        notification = Gio.Notification.new(title)
        notification.set_body(body)
        notification.set_icon(Gio.ThemedIcon.new(icon))
        notification.set_default_action("app.activate")
        notification.add_button("Re-authenticate", "app.reauth")
        self.app.send_notification("cert-expiry", notification)


class TrayIcon:
    """System tray icon using a helper subprocess (avoids GTK3/GTK4 conflict)."""

    def __init__(self, app, get_cert_info_fn):
        self.app = app
        self.get_cert_info = get_cert_info_fn
        self._proc = None

    @staticmethod
    def is_available():
        """Check if AppIndicator3 is available without importing GTK3."""
        try:
            result = subprocess.run(
                ["python3", "-c", "import gi; gi.require_version('AppIndicator3','0.1')"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def start(self):
        if self._proc is not None:
            return
        helper = os.path.join(os.path.dirname(__file__), "tray_helper.py")
        if not os.path.isfile(helper):
            return
        try:
            self._proc = subprocess.Popen(
                ["python3", helper],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def stop(self):
        if self._proc is not None:
            self._proc.terminate()
            self._proc = None


AUTOSTART_DIR = os.path.join(os.path.expanduser("~"), ".config", "autostart")
AUTOSTART_FILE = os.path.join(AUTOSTART_DIR, "vaultsign.desktop")


def enable_autostart():
    """Install autostart desktop entry."""
    os.makedirs(AUTOSTART_DIR, exist_ok=True)
    content = """[Desktop Entry]
Name=VaultSign
Comment=OIDC Authentication & SSH Key Signing
Exec=/opt/vaultsign/vaultsign --minimize
Icon=vaultsign
Terminal=false
Type=Application
X-GNOME-Autostart-enabled=true
"""
    with open(AUTOSTART_FILE, "w") as f:
        f.write(content)


def disable_autostart():
    """Remove autostart desktop entry."""
    if os.path.isfile(AUTOSTART_FILE):
        os.remove(AUTOSTART_FILE)


def is_autostart_enabled():
    """Check if autostart is configured."""
    return os.path.isfile(AUTOSTART_FILE)
