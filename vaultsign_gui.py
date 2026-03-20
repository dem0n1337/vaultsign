"""VaultSign GTK4/libadwaita GUI.

Main application window with all form fields, log output, and certificate
details view. Wired to vault_backend for async authentication execution.
"""

import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from config import load_config, save_config  # noqa: E402
from vault_backend import (  # noqa: E402
    check_token_status, list_oidc_roles, renew_token, request_cancel, reset_cancel, run_full_auth,
)

# Human-readable labels for each backend step.
_STEP_LABELS = {
    "check_prerequisites": "Checking prerequisites\u2026",
    "vault_login": "Logging in\u2026",
    "sign_ssh_key": "Signing key\u2026",
    "add_to_ssh_agent": "Adding to agent\u2026",
    "get_certificate_details": "Reading certificate details\u2026",
}


class VaultSignWindow(Adw.ApplicationWindow):
    """Main application window."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("VaultSign")
        self.set_default_size(520, 720)

        self.config = load_config()

        # --- Root layout: AdwToolbarView with header ---
        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        # Token status indicator in header
        self.token_status_button = Gtk.Button()
        self.token_status_button.add_css_class("flat")
        self.token_status_button.set_tooltip_text("Vault token status")
        self.token_status_button.connect("clicked", lambda _: self._update_token_status())

        token_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.token_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.token_label = Gtk.Label(label="No token")
        self.token_label.add_css_class("caption")
        token_box.append(self.token_icon)
        token_box.append(self.token_label)
        self.token_status_button.set_child(token_box)
        header.pack_start(self.token_status_button)

        # Hamburger menu
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_tooltip_text("Application menu")
        header.pack_end(menu_button)

        menu = Gio.Menu()
        theme_section = Gio.Menu()
        theme_section.append("System theme", "win.theme::system")
        theme_section.append("Light theme", "win.theme::light")
        theme_section.append("Dark theme", "win.theme::dark")
        menu.append_section("Theme", theme_section)

        about_section = Gio.Menu()
        about_section.append("About VaultSign", "win.about")
        menu.append_section(None, about_section)

        menu_button.set_menu_model(menu)

        # Theme action
        theme_action = Gio.SimpleAction.new_stateful(
            "theme", GLib.VariantType.new("s"),
            GLib.Variant.new_string(self.config.get("theme", "system"))
        )
        theme_action.connect("change-state", self._on_theme_changed)
        self.add_action(theme_action)

        # About action
        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._on_about)
        self.add_action(about_action)

        # Apply theme on startup
        self._apply_theme(self.config.get("theme", "system"))

        # Toast overlay wraps scrollable content so toasts appear on top
        self.toast_overlay = Adw.ToastOverlay()
        toolbar_view.set_content(self.toast_overlay)

        # Scrollable main content
        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        self.toast_overlay.set_child(scroll)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(12)
        main_box.set_margin_end(12)
        scroll.set_child(main_box)

        # --- Connection group ---
        conn_group = Adw.PreferencesGroup(title="Connection")
        main_box.append(conn_group)

        self.vault_addr_row = Adw.EntryRow(title="Vault Address")
        self.vault_addr_row.set_text(self.config.get("vault_addr", ""))
        conn_group.add(self.vault_addr_row)

        self.vault_cli_row = Adw.EntryRow(title="Vault CLI Path")
        self.vault_cli_row.set_text(self.config.get("vault_cli_path", ""))
        conn_group.add(self.vault_cli_row)

        self.ssh_key_row = Adw.EntryRow(title="SSH Key Path")
        self.ssh_key_row.set_text(self.config.get("ssh_key_path", ""))
        conn_group.add(self.ssh_key_row)

        # --- Authentication group ---
        auth_group = Adw.PreferencesGroup(title="Authentication")
        main_box.append(auth_group)

        # Saved roles combo row
        saved_roles = self.config.get("saved_roles", [])
        self.role_model = Gtk.StringList()
        for role in saved_roles:
            self.role_model.append(role)

        self.role_combo_row = Adw.ComboRow(title="Role", model=self.role_model)
        # Select the current role if it exists in saved_roles
        current_role = self.config.get("role", "")
        if current_role in saved_roles:
            self.role_combo_row.set_selected(saved_roles.index(current_role))
        fetch_roles_button = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        fetch_roles_button.set_tooltip_text("Fetch roles from Vault")
        fetch_roles_button.set_valign(Gtk.Align.CENTER)
        fetch_roles_button.add_css_class("flat")
        fetch_roles_button.connect("clicked", self._on_fetch_roles)
        self.role_combo_row.add_suffix(fetch_roles_button)
        auth_group.add(self.role_combo_row)

        # Custom role entry row (takes precedence when non-empty)
        self.custom_role_row = Adw.EntryRow(title="Custom Role (overrides dropdown)")
        auth_group.add(self.custom_role_row)

        # TTL selector
        self.ttl_model = Gtk.StringList.new(["Server default", "30m", "1h", "4h", "8h", "24h"])
        self.ttl_combo = Adw.ComboRow(title="Certificate TTL", model=self.ttl_model)
        auth_group.add(self.ttl_combo)

        self.custom_ttl_row = Adw.EntryRow(title="Custom TTL (e.g. 2h30m)")
        auth_group.add(self.custom_ttl_row)

        # --- Button area ---
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        button_box.set_halign(Gtk.Align.CENTER)
        button_box.set_margin_top(4)
        button_box.set_margin_bottom(4)
        main_box.append(button_box)

        self.auth_button = Gtk.Button(label="Authenticate")
        self.auth_button.add_css_class("suggested-action")
        self.auth_button.add_css_class("pill")
        self.auth_button.connect("clicked", self._on_authenticate)
        button_box.append(self.auth_button)

        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.add_css_class("destructive-action")
        self.cancel_button.add_css_class("pill")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self._on_cancel)
        button_box.append(self.cancel_button)

        self.save_button = Gtk.Button(label="Save Settings")
        self.save_button.add_css_class("flat")
        self.save_button.connect("clicked", self._on_save_settings)
        button_box.append(self.save_button)

        # --- Status group ---
        status_group = Adw.PreferencesGroup(title="Status")
        main_box.append(status_group)

        self.status_label = Gtk.Label(label="Ready")
        self.status_label.set_halign(Gtk.Align.START)
        self.status_label.set_margin_start(12)
        self.status_label.set_margin_end(12)
        self.status_label.set_margin_top(6)
        self.status_label.set_margin_bottom(6)
        self.status_label.add_css_class("dim-label")
        status_group.add(self.status_label)

        # --- Log output ---
        log_scroll = Gtk.ScrolledWindow(vexpand=True)
        log_scroll.set_min_content_height(160)
        main_box.append(log_scroll)

        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_monospace(True)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.log_view.set_top_margin(6)
        self.log_view.set_bottom_margin(6)
        self.log_view.set_left_margin(8)
        self.log_view.set_right_margin(8)
        self.log_buffer = self.log_view.get_buffer()
        self.log_buffer.set_text("Log output will appear here.\n")
        log_scroll.set_child(self.log_view)

        # --- Certificate details expander ---
        self.cert_expander = Gtk.Expander(label="Certificate Details")
        self.cert_expander.set_margin_top(4)
        main_box.append(self.cert_expander)

        cert_scroll = Gtk.ScrolledWindow()
        cert_scroll.set_min_content_height(120)
        self.cert_expander.set_child(cert_scroll)

        self.cert_view = Gtk.TextView()
        self.cert_view.set_editable(False)
        self.cert_view.set_cursor_visible(False)
        self.cert_view.set_monospace(True)
        self.cert_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.cert_view.set_top_margin(6)
        self.cert_view.set_bottom_margin(6)
        self.cert_view.set_left_margin(8)
        self.cert_view.set_right_margin(8)
        self.cert_buffer = self.cert_view.get_buffer()
        self.cert_buffer.set_text("No certificate loaded.")
        cert_scroll.set_child(self.cert_view)

        # --- Certificate expiry countdown ---
        self.cert_status_label = Gtk.Label(label="No certificate")
        self.cert_status_label.set_halign(Gtk.Align.START)
        self.cert_status_label.set_margin_start(12)
        self.cert_status_label.add_css_class("dim-label")
        main_box.append(self.cert_status_label)

        # Startup: check existing session and start timers
        GLib.idle_add(self._check_existing_session)
        self._update_cert_status()
        GLib.timeout_add_seconds(60, self._update_cert_status)
        GLib.timeout_add_seconds(120, self._update_token_status)
        GLib.timeout_add_seconds(120, self._check_and_renew_token)

        self._setup_shortcuts()

    # --- Helpers ---

    def get_active_role(self) -> str:
        """Return the role to use: custom entry if non-empty, else combo selection."""
        custom = self.custom_role_row.get_text().strip()
        if custom:
            return custom
        idx = self.role_combo_row.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION or idx >= self.role_model.get_n_items():
            return ""
        item = self.role_model.get_string(idx)
        return item if item else ""

    def _collect_config(self) -> dict:
        """Read current form values into a config dict."""
        role = self.get_active_role()
        saved_roles = [self.role_model.get_string(i) for i in range(self.role_model.get_n_items())]
        # Auto-add custom role to saved_roles
        if role and role not in saved_roles:
            saved_roles.append(role)
            self.role_model.append(role)
        # Get TTL
        custom_ttl = self.custom_ttl_row.get_text().strip()
        if custom_ttl:
            cert_ttl = custom_ttl
        else:
            ttl_idx = self.ttl_combo.get_selected()
            ttl_str = self.ttl_model.get_string(ttl_idx) if ttl_idx != Gtk.INVALID_LIST_POSITION else ""
            cert_ttl = "" if ttl_str == "Server default" else ttl_str

        return {
            "vault_addr": self.vault_addr_row.get_text().strip(),
            "vault_cli_path": self.vault_cli_row.get_text().strip(),
            "ssh_key_path": self.ssh_key_row.get_text().strip(),
            "role": role,
            "saved_roles": saved_roles,
            "cert_ttl": cert_ttl,
        }

    def _append_log(self, text: str) -> None:
        """Append text to the log buffer. Must be called on the main thread."""
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")
        # Auto-scroll to bottom
        end_iter = self.log_buffer.get_end_iter()
        self.log_view.scroll_to_iter(end_iter, 0.0, False, 0.0, 0.0)

    # --- Status monitoring ---

    def _update_cert_status(self) -> bool:
        """Update certificate expiry countdown. Returns True to keep timer running."""
        from cert_utils import parse_cert_expiry
        ssh_key = os.path.expanduser(self.config.get("ssh_key_path", ""))
        cert_path = ssh_key + "-cert.pub"
        info = parse_cert_expiry(cert_path)
        if info is None:
            self.cert_status_label.set_text("No certificate")
            self.cert_status_label.remove_css_class("error")
            return True
        if info["is_expired"]:
            self.cert_status_label.set_text("Certificate EXPIRED")
            self.cert_status_label.add_css_class("error")
        else:
            self.cert_status_label.set_text(f"Certificate valid for {info['remaining_human']}")
            self.cert_status_label.remove_css_class("error")
        return True

    def _update_token_status(self) -> bool:
        """Check vault token in background and update header indicator."""
        def _check():
            info = check_token_status(self._collect_config())

            def _update_ui():
                if info and info["ttl"] > 0:
                    hours = info["ttl"] // 3600
                    mins = (info["ttl"] % 3600) // 60
                    self.token_label.set_text(f"Token: {hours}h {mins}m")
                    self.token_icon.set_from_icon_name("emblem-ok-symbolic")
                else:
                    self.token_label.set_text("No token")
                    self.token_icon.set_from_icon_name("dialog-warning-symbolic")
                return False

            GLib.idle_add(_update_ui)

        threading.Thread(target=_check, daemon=True).start()
        return True

    def _check_existing_session(self):
        """Check if we already have a valid Vault token on startup."""
        def _check():
            info = check_token_status(self._collect_config())

            def _update_ui():
                if info and info["ttl"] > 0:
                    hours = info["ttl"] // 3600
                    mins = (info["ttl"] % 3600) // 60
                    self._append_log(f"Existing valid token found (TTL: {hours}h {mins}m)")
                    self.status_label.set_text(f"Authenticated (token: {hours}h {mins}m remaining)")
                    self._update_cert_status()
                    self._update_token_status()
                else:
                    self._append_log("No valid token found. Please authenticate.")
                return False

            GLib.idle_add(_update_ui)

        threading.Thread(target=_check, daemon=True).start()
        return False

    def _check_and_renew_token(self) -> bool:
        """Check token TTL and renew if below threshold."""
        def _do_renew():
            config = self._collect_config()
            info = check_token_status(config)
            if info and info.get("renewable") and info["ttl"] > 0 and info["ttl"] < 1800:
                ok, output = renew_token(config)
                def _notify():
                    if ok:
                        self._append_log("Token auto-renewed")
                        self._update_token_status()
                    return False
                GLib.idle_add(_notify)

        threading.Thread(target=_do_renew, daemon=True).start()
        return True

    def _setup_shortcuts(self):
        """Set up keyboard shortcuts."""
        app = self.get_application()

        action = Gio.SimpleAction.new("authenticate", None)
        action.connect("activate", lambda *_: self._on_authenticate(None) if self.auth_button.get_sensitive() else None)
        self.add_action(action)
        app.set_accels_for_action("win.authenticate", ["<Control>Return"])

        action = Gio.SimpleAction.new("save-settings", None)
        action.connect("activate", lambda *_: self._on_save_settings(None))
        self.add_action(action)
        app.set_accels_for_action("win.save-settings", ["<Control>s"])

        action = Gio.SimpleAction.new("cancel", None)
        action.connect("activate", lambda *_: self._on_cancel(None) if self.cancel_button.get_sensitive() else None)
        self.add_action(action)
        app.set_accels_for_action("win.cancel", ["Escape"])

    # --- Theme & About ---

    def _on_theme_changed(self, action, value):
        theme = value.get_string()
        action.set_state(value)
        self._apply_theme(theme)
        self.config["theme"] = theme
        save_config(self.config)

    def _apply_theme(self, theme: str):
        style_manager = Adw.StyleManager.get_default()
        if theme == "dark":
            style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        elif theme == "light":
            style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        else:
            style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)

    def _on_about(self, *args):
        dialog = Adw.AboutDialog(
            application_name="VaultSign",
            application_icon="dialog-password",
            developer_name="VaultSign Contributors",
            version="2.0.0",
            website="https://github.com/dem0n1337/vaultsign",
            issue_url="https://github.com/dem0n1337/vaultsign/issues",
            license_type=Gtk.License.MIT_X11,
            developers=["dem0n1337"],
            copyright="© 2026 VaultSign Contributors",
            comments="HashiCorp Vault OIDC Authentication & SSH Key Signing",
        )
        dialog.present(self)

    # --- Signal handlers ---

    def _on_fetch_roles(self, _button):
        """Fetch available roles from Vault in background."""
        self._append_log("Fetching roles from Vault...")

        def _fetch():
            roles = list_oidc_roles(self._collect_config())

            def _update_ui():
                if roles is None:
                    self._append_log("Could not fetch roles (need valid token first?)")
                    toast = Adw.Toast(title="Could not fetch roles")
                    self.toast_overlay.add_toast(toast)
                    return False

                existing = set(self.role_model.get_string(i) for i in range(self.role_model.get_n_items()))
                added = 0
                for role in roles:
                    if role not in existing:
                        self.role_model.append(role)
                        added += 1

                self._append_log(f"Found {len(roles)} roles, added {added} new.")
                toast = Adw.Toast(title=f"Found {len(roles)} roles")
                self.toast_overlay.add_toast(toast)
                return False

            GLib.idle_add(_update_ui)

        threading.Thread(target=_fetch, daemon=True).start()

    def _on_save_settings(self, _button):
        """Persist current form values to config.json and show a toast."""
        self.config = self._collect_config()
        save_config(self.config)
        self.status_label.set_text("Settings saved.")
        toast = Adw.Toast(title="Settings saved")
        self.toast_overlay.add_toast(toast)

    def _on_cancel(self, _button):
        """Request cancellation of the running auth flow."""
        request_cancel()
        self.cancel_button.set_sensitive(False)
        self.status_label.set_text("Cancelling\u2026")

    def _on_authenticate(self, _button):
        """Collect config, disable button, and run auth in a background thread."""
        config = self._collect_config()
        reset_cancel()

        # Disable button and clear log
        self.auth_button.set_sensitive(False)
        self.cancel_button.set_sensitive(True)
        self.log_buffer.set_text("")
        self.cert_buffer.set_text("No certificate loaded.")
        self.cert_expander.set_expanded(False)
        self.status_label.set_text("Authenticating\u2026")

        def step_callback(step_name: str, success: bool, output: str) -> None:
            """Called from worker thread after each step completes."""
            status = "OK" if success else "FAILED"
            label = _STEP_LABELS.get(step_name, step_name)

            def _update_ui():
                self._append_log(f"[{step_name}] {status}")
                if output:
                    self._append_log(output)
                self.status_label.set_text(label)
                return False  # Remove idle source

            GLib.idle_add(_update_ui)

        def worker() -> None:
            """Run the full auth flow in a background thread."""
            try:
                success, output = run_full_auth(config, step_callback=step_callback)
            except Exception as e:
                success, output = False, f"Unexpected error: {e}"

            def _finish():
                self.auth_button.set_sensitive(True)
                self.cancel_button.set_sensitive(False)
                if success:
                    self.status_label.set_text("Authentication successful.")
                    # Populate certificate details from the last step output
                    self.cert_buffer.set_text(output)
                    self.cert_expander.set_expanded(True)
                    self._update_cert_status()
                    self._update_token_status()
                else:
                    first_line = output.split("\n")[0][:80]
                    self.status_label.set_text(f"Error: {first_line}")
                return False

            GLib.idle_add(_finish)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()


class VaultSignApp(Adw.Application):
    """Application entry point."""

    def __init__(self):
        super().__init__(application_id="io.github.dem0n1337.vaultsign")

    def do_activate(self):
        win = VaultSignWindow(application=self)
        win.present()


def main():
    app = VaultSignApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
