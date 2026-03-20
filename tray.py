"""Certificate expiry notification support for VaultSign."""

from gi.repository import Gio, GLib


class ExpiryMonitor:
    """Monitors certificate expiry and sends desktop notifications."""

    def __init__(self, app, config, get_cert_info_fn):
        self.app = app
        self.config = config
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

        warn_minutes = self.config.get("expiry_warn_minutes", 30)
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
        self.app.send_notification("cert-expiry", notification)
