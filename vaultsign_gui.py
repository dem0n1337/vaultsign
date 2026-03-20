"""VaultSign GTK4/libadwaita GUI.

Main application window with all form fields, log output, and certificate
details view. Wired to vault_backend for async authentication execution.
"""

import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from config import load_config, save_config  # noqa: E402
from vault_backend import run_full_auth  # noqa: E402

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
        auth_group.add(self.role_combo_row)

        # Custom role entry row (takes precedence when non-empty)
        self.custom_role_row = Adw.EntryRow(title="Custom Role (overrides dropdown)")
        auth_group.add(self.custom_role_row)

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
        return {
            "vault_addr": self.vault_addr_row.get_text().strip(),
            "vault_cli_path": self.vault_cli_row.get_text().strip(),
            "ssh_key_path": self.ssh_key_row.get_text().strip(),
            "role": role,
            "saved_roles": saved_roles,
        }

    def _append_log(self, text: str) -> None:
        """Append text to the log buffer. Must be called on the main thread."""
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")

    # --- Signal handlers ---

    def _on_save_settings(self, _button):
        """Persist current form values to config.json and show a toast."""
        self.config = self._collect_config()
        save_config(self.config)
        self.status_label.set_text("Settings saved.")
        toast = Adw.Toast(title="Settings saved")
        self.toast_overlay.add_toast(toast)

    def _on_authenticate(self, _button):
        """Collect config, disable button, and run auth in a background thread."""
        config = self._collect_config()

        # Disable button and clear log
        self.auth_button.set_sensitive(False)
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
            success, output = run_full_auth(config, step_callback=step_callback)

            def _finish():
                self.auth_button.set_sensitive(True)
                if success:
                    self.status_label.set_text("Authentication successful.")
                    # Populate certificate details from the last step output
                    self.cert_buffer.set_text(output)
                    self.cert_expander.set_expanded(True)
                else:
                    self.status_label.set_text(f"Error: {output}")
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
