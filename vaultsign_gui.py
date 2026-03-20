"""VaultSign GTK4/libadwaita GUI.

Main application window with all form fields, log output, and certificate
details view. Wired to vault_backend for async authentication execution.
"""

import copy
import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from config import load_config, save_config, get_active_profile, set_active_profile, save_profile, delete_profile, list_profiles, DEFAULTS, CONFIG_FILE  # noqa: E402
from vault_backend import (  # noqa: E402
    check_token_status, check_vault_status, redact_tokens, renew_token, request_cancel, reset_cancel, run_full_auth,
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
        self.set_default_size(360, 550)
        self.set_resizable(False)

        self._is_first_run = not CONFIG_FILE.exists()
        self.config = load_config()
        self.profile = get_active_profile(self.config)

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

        # Vault status section (dynamic, updated by _update_vault_status)
        self._vault_status_menu = Gio.Menu()
        self._vault_status_menu.append("Vault: checking...", None)
        menu.append_section(None, self._vault_status_menu)

        log_section = Gio.Menu()
        log_section.append("Copy Log to Clipboard", "win.copy-log")
        log_section.append("Save Log to File", "win.save-log")
        menu.append_section("Log", log_section)

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

        # --- Profile group ---
        profile_group = Adw.PreferencesGroup(title="Profile")
        main_box.append(profile_group)

        profile_names = list_profiles(self.config)
        self.profile_model = Gtk.StringList()
        for name in profile_names:
            self.profile_model.append(name)

        self.profile_combo = Adw.ComboRow(title="Active Profile", model=self.profile_model)
        active = self.config.get("active_profile", "default")
        if active in profile_names:
            self.profile_combo.set_selected(profile_names.index(active))
        self.profile_combo.connect("notify::selected", self._on_profile_switched)
        profile_group.add(self.profile_combo)

        add_profile_btn = Gtk.Button.new_from_icon_name("list-add-symbolic")
        add_profile_btn.set_tooltip_text("Add new profile")
        add_profile_btn.set_valign(Gtk.Align.CENTER)
        add_profile_btn.add_css_class("flat")
        add_profile_btn.connect("clicked", self._on_add_profile)
        self.profile_combo.add_suffix(add_profile_btn)

        del_profile_btn = Gtk.Button.new_from_icon_name("list-remove-symbolic")
        del_profile_btn.set_tooltip_text("Delete current profile")
        del_profile_btn.set_valign(Gtk.Align.CENTER)
        del_profile_btn.add_css_class("flat")
        del_profile_btn.connect("clicked", self._on_delete_profile)
        self.profile_combo.add_suffix(del_profile_btn)

        # --- Connection group ---
        conn_group = Adw.PreferencesGroup(title="Connection")
        main_box.append(conn_group)

        self.vault_addr_row = Adw.EntryRow(title="Vault Address")
        self.vault_addr_row.set_text(self.profile.get("vault_addr", ""))
        conn_group.add(self.vault_addr_row)

        self.vault_cli_row = Adw.EntryRow(title="Vault CLI Path")
        self.vault_cli_row.set_text(self.profile.get("vault_cli_path", ""))
        conn_group.add(self.vault_cli_row)

        self.ssh_key_row = Adw.EntryRow(title="SSH Key Path")
        self.ssh_key_row.set_text(self.profile.get("ssh_key_path", ""))
        conn_group.add(self.ssh_key_row)

        # --- Authentication group ---
        auth_group = Adw.PreferencesGroup(title="Authentication")
        main_box.append(auth_group)

        self.role_row = Adw.EntryRow(title="Role")
        self.role_row.set_text(self.profile.get("role", ""))
        auth_group.add(self.role_row)

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

        # Hidden log buffer (accessible via hamburger menu -> Copy/Save Log)
        self.log_buffer = Gtk.TextBuffer()
        self.log_buffer.set_text("")

        # Startup: check existing session and start timers
        GLib.idle_add(self._check_existing_session)


        GLib.timeout_add_seconds(120, self._update_token_status)
        GLib.timeout_add_seconds(120, self._check_and_renew_token)
        self._update_vault_status()
        GLib.timeout_add_seconds(30, self._update_vault_status)

        self._setup_shortcuts()

        if self._is_first_run:
            GLib.idle_add(self._show_first_run_wizard)

    # --- Helpers ---

    def _collect_config(self) -> dict:
        """Read current form values into a config dict."""
        return {
            "vault_addr": self.vault_addr_row.get_text().strip(),
            "vault_cli_path": self.vault_cli_row.get_text().strip(),
            "ssh_key_path": self.ssh_key_row.get_text().strip(),
            "role": self.role_row.get_text().strip(),
        }

    def _append_log(self, text: str) -> None:
        """Append text to the hidden log buffer."""
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")

    # --- Status monitoring ---

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

    def _update_vault_status(self) -> bool:
        """Check Vault server status in background."""
        def _check():
            status = check_vault_status(self._collect_config())
            def _update():
                self._vault_status_menu.remove_all()
                if status is None:
                    self._vault_status_menu.append("Vault: unreachable", None)
                elif status["sealed"]:
                    self._vault_status_menu.append("Vault: sealed", None)
                else:
                    self._vault_status_menu.append(f"Vault: ok (v{status['version']})", None)
                return False
            GLib.idle_add(_update)
        threading.Thread(target=_check, daemon=True).start()
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

        action = Gio.SimpleAction.new("copy-log", None)
        action.connect("activate", lambda *_: self._on_copy_log(None))
        self.add_action(action)
        app.set_accels_for_action("win.copy-log", ["<Control>l"])

        action = Gio.SimpleAction.new("save-log", None)
        action.connect("activate", lambda *_: self._on_save_log(None))
        self.add_action(action)

    # --- Profile management ---

    def _on_profile_switched(self, combo, _pspec):
        idx = combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION:
            return
        name = self.profile_model.get_string(idx)
        self.profile = set_active_profile(self.config, name)
        self._populate_fields(self.profile)
        save_config(self.config)

    def _populate_fields(self, profile: dict):
        """Fill form fields from a profile dict."""
        self.vault_addr_row.set_text(profile.get("vault_addr", ""))
        self.vault_cli_row.set_text(profile.get("vault_cli_path", ""))
        self.ssh_key_row.set_text(profile.get("ssh_key_path", ""))
        self.role_row.set_text(profile.get("role", ""))

    def _on_add_profile(self, _button):
        dialog = Adw.MessageDialog(transient_for=self, heading="New Profile", body="Enter profile name:")
        entry = Gtk.Entry()
        entry.set_placeholder_text("e.g. staging")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("create", "Create")
        dialog.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self._on_add_profile_response, entry)
        dialog.present()

    def _on_add_profile_response(self, dialog, response, entry):
        if response == "create":
            name = entry.get_text().strip()
            if name and name not in list_profiles(self.config):
                save_profile(self.config, name, copy.deepcopy(DEFAULTS))
                self.profile_model.append(name)
                self.profile_combo.set_selected(self.profile_model.get_n_items() - 1)
                save_config(self.config)

    def _on_delete_profile(self, _button):
        idx = self.profile_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION:
            return
        name = self.profile_model.get_string(idx)
        if delete_profile(self.config, name):
            self.profile_model.remove(idx)
            new_active = self.config.get("active_profile", "default")
            names = list_profiles(self.config)
            if new_active in names:
                self.profile_combo.set_selected(names.index(new_active))
            save_config(self.config)
        else:
            toast = Adw.Toast(title="Cannot delete the last profile")
            self.toast_overlay.add_toast(toast)

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
            comments="HashiCorp Vault OIDC Authentication and SSH Key Signing",
        )
        dialog.present(self)

    # --- Log export ---

    def _on_copy_log(self, _button):
        """Copy log contents to clipboard."""
        start = self.log_buffer.get_start_iter()
        end = self.log_buffer.get_end_iter()
        text = self.log_buffer.get_text(start, end, False)
        clipboard = self.get_clipboard()
        clipboard.set(text)
        toast = Adw.Toast(title="Log copied to clipboard")
        self.toast_overlay.add_toast(toast)

    def _on_save_log(self, _button):
        """Save log to a file using file chooser dialog."""
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("vaultsign.log")
        dialog.save(self, None, self._on_save_log_response)

    def _on_save_log_response(self, dialog, result):
        try:
            file = dialog.save_finish(result)
            if file:
                start = self.log_buffer.get_start_iter()
                end = self.log_buffer.get_end_iter()
                text = self.log_buffer.get_text(start, end, False)
                path = file.get_path()
                with open(path, "w") as f:
                    f.write(text)
                toast = Adw.Toast(title=f"Log saved to {os.path.basename(path)}")
                self.toast_overlay.add_toast(toast)
        except Exception:
            pass  # User cancelled

    # --- Signal handlers ---

    def _on_save_settings(self, _button):
        """Persist current form values to config.json and show a toast."""
        profile_data = self._collect_config()
        active = self.config.get("active_profile", "default")
        save_profile(self.config, active, profile_data)
        save_config(self.config)
        toast = Adw.Toast(title="Settings saved")
        self.toast_overlay.add_toast(toast)

    def _on_cancel(self, _button):
        """Request cancellation of the running auth flow."""
        request_cancel()
        self.cancel_button.set_sensitive(False)

    def _show_first_run_wizard(self):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Welcome to VaultSign",
            body="Let's set up your Vault connection.\n\nYou can change these settings later.",
        )

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_top(8)

        addr_entry = Adw.EntryRow(title="Vault Address")
        addr_entry.set_text(self.profile.get("vault_addr", ""))
        box.append(addr_entry)

        cli_entry = Adw.EntryRow(title="Vault CLI Path")
        cli_entry.set_text(self.profile.get("vault_cli_path", ""))
        box.append(cli_entry)

        key_entry = Adw.EntryRow(title="SSH Key Path")
        key_entry.set_text(self.profile.get("ssh_key_path", ""))
        box.append(key_entry)

        role_entry = Adw.EntryRow(title="Default Role")
        role_entry.set_text(self.profile.get("role", ""))
        box.append(role_entry)

        dialog.set_extra_child(box)
        dialog.add_response("skip", "Skip")
        dialog.add_response("save", "Save & Continue")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self._on_wizard_response, addr_entry, cli_entry, key_entry, role_entry)
        dialog.present()
        return False

    def _on_wizard_response(self, dialog, response, addr_entry, cli_entry, key_entry, role_entry):
        if response == "save":
            self.vault_addr_row.set_text(addr_entry.get_text())
            self.vault_cli_row.set_text(cli_entry.get_text())
            self.ssh_key_row.set_text(key_entry.get_text())
            role = role_entry.get_text().strip()
            if role:
                self.role_row.set_text(role)
            self._on_save_settings(None)

    def _on_authenticate(self, _button):
        """Collect config, disable button, and run auth in a background thread."""
        config = self._collect_config()
        reset_cancel()

        # Disable button and clear log
        self.auth_button.set_sensitive(False)
        self.cancel_button.set_sensitive(True)
        self.log_buffer.set_text("")
        self.toast_overlay.add_toast(Adw.Toast(title="Authenticating\u2026"))

        def step_callback(step_name: str, success: bool, output: str) -> None:
            """Called from worker thread after each step completes."""
            output = redact_tokens(output) if output else output
            status = "OK" if success else "FAILED"
            label = _STEP_LABELS.get(step_name, step_name)

            def _update_ui():
                self._append_log(f"[{step_name}] {status}")
                if output:
                    self._append_log(output)
                self.toast_overlay.add_toast(Adw.Toast(title=label))
                return False  # Remove idle source

            GLib.idle_add(_update_ui)

        def worker() -> None:
            """Run the full auth flow in a background thread."""
            try:
                success, output = run_full_auth(config, step_callback=step_callback)
            except Exception as e:
                success, output = False, f"Unexpected error: {e}"

            def _finish():
                nonlocal output
                output = redact_tokens(output)
                self.auth_button.set_sensitive(True)
                self.cancel_button.set_sensitive(False)
                if success:
                    self.toast_overlay.add_toast(Adw.Toast(title="Authentication successful."))
                    self._update_token_status()
                else:
                    first_line = output.split("\n")[0][:80]
                    self.toast_overlay.add_toast(Adw.Toast(title=f"Error: {first_line}"))
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

        from tray import ExpiryMonitor
        from cert_utils import parse_cert_expiry

        profile = get_active_profile(win.config)

        def get_cert_info():
            ssh_key = os.path.expanduser(profile.get("ssh_key_path", ""))
            return parse_cert_expiry(ssh_key + "-cert.pub")

        self.expiry_monitor = ExpiryMonitor(self, profile, get_cert_info)
        if profile.get("show_tray", True):
            self.expiry_monitor.start()

        import webbrowser
        from updater import check_for_update

        def _check_update():
            update_info = check_for_update()
            if update_info:
                def _notify():
                    toast = Adw.Toast(title=f"VaultSign {update_info['version']} available")
                    toast.set_button_label("Details")
                    toast.connect("button-clicked", lambda _: webbrowser.open(update_info["url"]))
                    win.toast_overlay.add_toast(toast)
                    return False
                GLib.idle_add(_notify)

        threading.Thread(target=_check_update, daemon=True).start()


def main():
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error):
        pass

    app = VaultSignApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
