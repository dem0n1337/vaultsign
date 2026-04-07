#!/usr/bin/env python3
"""Standalone tray icon helper for VaultSign.

Runs as a separate process to avoid GTK3/GTK4 conflict.
Communicates with the main app via Gio D-Bus activation.
"""

import os
import signal
import sys

import gi
gi.require_version("AppIndicator3", "0.1")
gi.require_version("Gtk", "3.0")

from gi.repository import AppIndicator3, GLib, Gtk

sys.path.insert(0, os.path.dirname(__file__))
from cert_utils import parse_cert_expiry
from config import load_config, get_active_profile

APP_ID = "io.github.dem0n1337.vaultsign"


def get_cert_info():
    config = load_config()
    profile = get_active_profile(config)
    ssh_key = os.path.expanduser(profile.get("ssh_key_path", ""))
    return parse_cert_expiry(ssh_key + "-cert.pub")


def activate_app():
    """Activate the main VaultSign window via D-Bus."""
    try:
        from gi.repository import Gio
        bus = Gio.bus_get_sync(Gio.BusType.SESSION)
        bus.call_sync(
            APP_ID, "/" + APP_ID.replace(".", "/"),
            "org.freedesktop.Application", "Activate",
            GLib.Variant("(a{sv})", [{}]),
            None, Gio.DBusCallFlags.NONE, -1, None,
        )
    except Exception:
        # Fallback: just launch the binary
        os.spawnl(os.P_NOWAIT, "/opt/vaultsign/vaultsign", "vaultsign")


def main():
    signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())

    icon_path = os.path.join(os.path.dirname(__file__), "icons", "vaultsign-48.png")

    indicator = AppIndicator3.Indicator.new(
        "vaultsign",
        icon_path if os.path.isfile(icon_path) else "dialog-password",
        AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
    )
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)

    menu = Gtk.Menu()

    show_item = Gtk.MenuItem(label="Show VaultSign")
    show_item.connect("activate", lambda _: activate_app())
    menu.append(show_item)

    status_item = Gtk.MenuItem(label="No active session")
    status_item.set_sensitive(False)
    menu.append(status_item)

    menu.append(Gtk.SeparatorMenuItem())

    quit_item = Gtk.MenuItem(label="Quit VaultSign")
    quit_item.connect("activate", lambda _: Gtk.main_quit())
    menu.append(quit_item)

    menu.show_all()
    indicator.set_menu(menu)

    def update_status():
        info = get_cert_info()
        if info and not info["is_expired"]:
            status_item.set_label(f"Certificate: {info['remaining_human']} left")
        elif info and info["is_expired"]:
            status_item.set_label("Certificate expired")
        else:
            status_item.set_label("No active session")
        return True

    update_status()
    GLib.timeout_add_seconds(60, update_status)

    Gtk.main()


if __name__ == "__main__":
    main()
