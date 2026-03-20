"""VaultSign GTK4/libadwaita GUI.

Main application window with all form fields, log output, and certificate
details view. Backend wiring is handled separately (Task 4).
"""

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from config import load_config, save_config  # noqa: E402


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

        # Scrollable main content
        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        toolbar_view.set_content(scroll)

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
            "vault_addr": self.vault_addr_row.get_text(),
            "vault_cli_path": self.vault_cli_row.get_text(),
            "ssh_key_path": self.ssh_key_row.get_text(),
            "role": role,
            "saved_roles": saved_roles,
        }

    def _on_save_settings(self, _button):
        """Persist current form values to config.json."""
        self.config = self._collect_config()
        save_config(self.config)
        self.status_label.set_text("Settings saved.")


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
