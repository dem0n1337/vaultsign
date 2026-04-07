"""VaultSign GTK4/libadwaita GUI.

Main application window with all form fields, log output, and certificate
details view. Wired to vault_backend for async authentication execution.
"""

import copy
import math
import os
import shutil
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from config import load_config, save_config, get_active_profile, set_active_profile, save_profile, delete_profile, list_profiles, export_profile, import_profile, append_history, load_history, clear_history, DEFAULTS, CONFIG_FILE  # noqa: E402
from logger import setup_logging  # noqa: E402
from updater import VERSION  # noqa: E402
from vault_backend import (  # noqa: E402
    check_token_status, check_vault_status, detect_cli, get_key_fingerprint, install_cli, list_agent_keys, redact_tokens, renew_token, request_cancel, reset_cancel, run_full_auth,
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
        self._logger = setup_logging()
        self.config = load_config()
        self.profile = get_active_profile(self.config)

        # --- Root layout: NavigationView for in-window page transitions ---
        self.nav_view = Adw.NavigationView()
        self.set_content(self.nav_view)

        # Main page
        main_page = Adw.NavigationPage(title="VaultSign", tag="main")
        toolbar_view = Adw.ToolbarView()
        main_page.set_child(toolbar_view)
        self.nav_view.add(main_page)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

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

        startup_section = Gio.Menu()
        startup_section.append("Start at Login", "win.autostart")
        startup_section.append("Show Tray Icon", "win.show-tray")
        menu.append_section("Startup", startup_section)

        history_section = Gio.Menu()
        history_section.append("Session History", "win.history")
        menu.append_section(None, history_section)

        about_section = Gio.Menu()
        about_section.append("About VaultSign", "win.about")
        about_section.append("Quit", "app.quit")
        menu.append_section(None, about_section)

        menu_button.set_menu_model(menu)

        # Theme action
        theme_action = Gio.SimpleAction.new_stateful(
            "theme", GLib.VariantType.new("s"),
            GLib.Variant.new_string(self.config.get("theme", "system"))
        )
        theme_action.connect("change-state", self._on_theme_changed)
        self.add_action(theme_action)

        # Autostart toggle
        from tray import is_autostart_enabled
        autostart_action = Gio.SimpleAction.new_stateful(
            "autostart", None,
            GLib.Variant.new_boolean(is_autostart_enabled()),
        )
        autostart_action.connect("change-state", self._on_autostart_toggled)
        self.add_action(autostart_action)

        # Show tray toggle
        show_tray_action = Gio.SimpleAction.new_stateful(
            "show-tray", None,
            GLib.Variant.new_boolean(get_active_profile(self.config).get("show_tray", True)),
        )
        show_tray_action.connect("change-state", self._on_show_tray_toggled)
        self.add_action(show_tray_action)

        # History action
        history_action = Gio.SimpleAction.new("history", None)
        history_action.connect("activate", self._on_history)
        self.add_action(history_action)

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

        # --- Session status group (clickable, navigates to session page) ---
        session_group = Adw.PreferencesGroup()
        main_box.append(session_group)

        self.session_row = Adw.ActionRow(
            title="Session",
            subtitle="No active session",
        )
        self.session_row.set_activatable(True)
        self.session_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self.session_row.add_prefix(self.session_icon)
        self.session_row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        self.session_row.connect("activated", lambda _: self._push_session_page())
        session_group.add(self.session_row)

        self.agent_row = Adw.ActionRow(
            title="SSH Agent",
            subtitle="Checking…",
        )
        self.agent_icon = Gtk.Image.new_from_icon_name("system-run-symbolic")
        self.agent_row.add_prefix(self.agent_icon)
        session_group.add(self.agent_row)

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

        profile_io_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        profile_io_box.set_margin_top(4)

        export_btn = Gtk.Button(label="Export Profile")
        export_btn.add_css_class("flat")
        export_btn.connect("clicked", self._on_export_profile)
        profile_io_box.append(export_btn)

        import_btn = Gtk.Button(label="Import Profile")
        import_btn.add_css_class("flat")
        import_btn.connect("clicked", self._on_import_profile)
        profile_io_box.append(import_btn)

        profile_group.set_header_suffix(profile_io_box)

        # --- Connection group ---
        conn_group = Adw.PreferencesGroup(title="Connection")
        main_box.append(conn_group)

        self.vault_addr_row = Adw.EntryRow(title="Server Address")
        self.vault_addr_row.set_text(self.profile.get("vault_addr", ""))
        conn_group.add(self.vault_addr_row)

        self.vault_cli_row = Adw.EntryRow(title="CLI Path (vault / bao)")
        self.vault_cli_row.set_text(self.profile.get("vault_cli_path", ""))
        cli_browse = Gtk.Button.new_from_icon_name("document-open-symbolic")
        cli_browse.set_valign(Gtk.Align.CENTER)
        cli_browse.add_css_class("flat")
        cli_browse.set_tooltip_text("Browse for CLI binary")
        cli_browse.connect("clicked", lambda _: self._browse_file(self.vault_cli_row))
        self.vault_cli_row.add_suffix(cli_browse)
        conn_group.add(self.vault_cli_row)

        self.ssh_key_row = Adw.EntryRow(title="SSH Key Path")
        self.ssh_key_row.set_text(self.profile.get("ssh_key_path", ""))
        key_browse = Gtk.Button.new_from_icon_name("document-open-symbolic")
        key_browse.set_valign(Gtk.Align.CENTER)
        key_browse.add_css_class("flat")
        key_browse.set_tooltip_text("Browse for SSH key")
        key_browse.connect("clicked", lambda _: self._browse_file(self.ssh_key_row))
        self.ssh_key_row.add_suffix(key_browse)
        conn_group.add(self.ssh_key_row)

        self.signer_path_row = Adw.EntryRow(title="SSH Signer Mount Path")
        self.signer_path_row.set_text(self.profile.get("ssh_signer_path", "ssh-client-signer"))
        conn_group.add(self.signer_path_row)

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

        # Auto-hide on idle (reset on any key/click)
        key_ctrl = Gtk.EventControllerKey()
        key_ctrl.connect("key-pressed", lambda *_: self._reset_idle_timer() or False)
        self.add_controller(key_ctrl)
        click_ctrl = Gtk.GestureClick()
        click_ctrl.connect("pressed", lambda *_: self._reset_idle_timer())
        self.add_controller(click_ctrl)
        self._idle_timer_id = None
        self._start_idle_timer()

    # --- Helpers ---

    def _browse_file(self, entry_row):
        """Open a file chooser and set the result into the entry row."""
        dialog = Gtk.FileDialog()
        current = entry_row.get_text().strip()
        if current:
            expanded = os.path.expanduser(current)
            parent = os.path.dirname(expanded)
            if os.path.isdir(parent):
                dialog.set_initial_folder(Gio.File.new_for_path(parent))
        dialog.open(self, None, lambda d, r: self._on_file_chosen(d, r, entry_row))

    def _on_file_chosen(self, dialog, result, entry_row):
        try:
            file = dialog.open_finish(result)
            if file:
                entry_row.set_text(file.get_path())
        except Exception:
            pass  # User cancelled

    def _start_idle_timer(self):
        """Auto-hide the window after 10 minutes of inactivity."""
        if hasattr(self, "_idle_timer_id") and self._idle_timer_id is not None:
            GLib.source_remove(self._idle_timer_id)
        self._idle_timer_id = GLib.timeout_add_seconds(600, self._on_idle_timeout)

    def _on_idle_timeout(self):
        self._idle_timer_id = None
        if self.is_visible():
            self.set_visible(False)
        return False  # One-shot

    def _reset_idle_timer(self, *_args):
        self._start_idle_timer()

    def _clipboard_set_with_autoclear(self, text, seconds=30):
        """Set clipboard and auto-clear it after the given seconds."""
        clipboard = self.get_clipboard()
        clipboard.set(text)
        GLib.timeout_add_seconds(seconds, lambda: clipboard.set("") or False)

    def _collect_config(self) -> dict:
        """Read current form values into a config dict."""
        return {
            "vault_addr": self.vault_addr_row.get_text().strip(),
            "vault_cli_path": self.vault_cli_row.get_text().strip(),
            "ssh_key_path": self.ssh_key_row.get_text().strip(),
            "ssh_signer_path": self.signer_path_row.get_text().strip() or "ssh-client-signer",
            "role": self.role_row.get_text().strip(),
        }

    def _append_log(self, text: str) -> None:
        """Append text to the hidden log buffer and file log."""
        self._logger.info(text)
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text + "\n")

    # --- Status monitoring ---

    def _update_token_status(self) -> bool:
        """Check vault token and cert in background and update the session row."""
        config = self._collect_config()
        def _check():
            from cert_utils import parse_cert_expiry
            token = check_token_status(config)
            ssh_key = os.path.expanduser(config.get("ssh_key_path", ""))
            cert = parse_cert_expiry(ssh_key + "-cert.pub")
            agent_keys = list_agent_keys()

            # Check if configured key is loaded in agent (by fingerprint)
            key_loaded = False
            configured_fp = get_key_fingerprint(ssh_key + ".pub")
            for k in agent_keys:
                if configured_fp and k.get("fingerprint") == configured_fp:
                    key_loaded = True
                    break
                comment = k.get("comment", "")
                if comment and (
                    os.path.normpath(comment) == os.path.normpath(ssh_key)
                    or os.path.normpath(comment) == os.path.normpath(ssh_key + "-cert.pub")
                ):
                    key_loaded = True
                    break

            def _update_ui():
                if cert and not cert["is_expired"]:
                    self.session_row.set_title("Session Active")
                    self.session_row.set_subtitle(f"Certificate valid for {cert['remaining_human']}")
                    self.session_icon.set_from_icon_name("emblem-ok-symbolic")
                elif token and token["ttl"] > 0:
                    hours = token["ttl"] // 3600
                    mins = (token["ttl"] % 3600) // 60
                    self.session_row.set_title("Token Active")
                    self.session_row.set_subtitle(f"Token valid for {hours}h {mins}m")
                    self.session_icon.set_from_icon_name("emblem-ok-symbolic")
                else:
                    self.session_row.set_title("Session")
                    self.session_row.set_subtitle("No active session")
                    self.session_icon.set_from_icon_name("dialog-warning-symbolic")

                # Agent status
                n = len(agent_keys)
                if n == 0:
                    self.agent_row.set_subtitle("No keys loaded")
                    self.agent_icon.set_from_icon_name("dialog-warning-symbolic")
                elif key_loaded:
                    self.agent_row.set_subtitle(f"{n} key{'s' if n != 1 else ''} loaded · Configured key active")
                    self.agent_icon.set_from_icon_name("emblem-ok-symbolic")
                else:
                    self.agent_row.set_subtitle(f"{n} key{'s' if n != 1 else ''} loaded · Configured key missing")
                    self.agent_icon.set_from_icon_name("dialog-warning-symbolic")
                return False

            GLib.idle_add(_update_ui)

        threading.Thread(target=_check, daemon=True).start()
        return True

    def _check_existing_session(self):
        """Check if we already have a valid Vault token on startup."""
        config = self._collect_config()
        def _check():
            from cert_utils import parse_cert_expiry
            info = check_token_status(config)
            ssh_key = os.path.expanduser(config.get("ssh_key_path", ""))
            cert = parse_cert_expiry(ssh_key + "-cert.pub")

            has_session = (cert and not cert["is_expired"]) or (info and info["ttl"] > 0)

            def _update_ui():
                self._update_token_status()
                if has_session:
                    self._append_log("Existing valid session found.")
                    GLib.timeout_add(300, self._push_session_page)
                else:
                    self._append_log("No valid session found. Please authenticate.")
                return False

            GLib.idle_add(_update_ui)

        threading.Thread(target=_check, daemon=True).start()
        return False

    def _check_and_renew_token(self) -> bool:
        """Check token TTL and renew if below threshold."""
        config = self._collect_config()
        def _do_renew():
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
        config = self._collect_config()
        def _check():
            status = check_vault_status(config)
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
        self.signer_path_row.set_text(profile.get("ssh_signer_path", "ssh-client-signer"))
        self.role_row.set_text(profile.get("role", ""))

    def _on_add_profile(self, _button):
        dialog = Adw.AlertDialog(heading="New Profile", body="Enter profile name:")
        entry = Gtk.Entry()
        entry.set_placeholder_text("e.g. staging")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("create", "Create")
        dialog.set_response_appearance("create", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self._on_add_profile_response, entry)
        dialog.present(self)

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
            toast = Adw.Toast(title="Cannot delete the last profile", timeout=2)
            self.toast_overlay.add_toast(toast)

    # --- Profile export/import ---

    def _on_export_profile(self, _button):
        idx = self.profile_combo.get_selected()
        if idx == Gtk.INVALID_LIST_POSITION:
            return
        name = self.profile_model.get_string(idx)
        data = export_profile(self.config, name)
        if not data:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name(f"vaultsign-profile-{name}.json")
        dialog.save(self, None, lambda d, r: self._on_export_profile_response(d, r, data))

    def _on_export_profile_response(self, dialog, result, data):
        import json
        try:
            file = dialog.save_finish(result)
            if file:
                path = file.get_path()
                with open(path, "w") as f:
                    json.dump(data, f, indent=2)
                self.toast_overlay.add_toast(Adw.Toast(title="Profile exported", timeout=2))
        except GLib.Error:
            pass

    def _on_import_profile(self, _button):
        dialog = Gtk.FileDialog()
        json_filter = Gtk.FileFilter()
        json_filter.set_name("JSON files")
        json_filter.add_pattern("*.json")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(json_filter)
        dialog.set_filters(filters)
        dialog.open(self, None, self._on_import_profile_response)

    def _on_import_profile_response(self, dialog, result):
        import json
        try:
            file = dialog.open_finish(result)
            if not file:
                return
            path = file.get_path()
            with open(path, "r") as f:
                data = json.load(f)
            name = import_profile(self.config, data)
            if name is None:
                self.toast_overlay.add_toast(Adw.Toast(title="Invalid profile file", timeout=2))
                return
            save_config(self.config)
            self.profile_model.append(name)
            names = list_profiles(self.config)
            self.profile_combo.set_selected(names.index(name))
            self.toast_overlay.add_toast(Adw.Toast(title=f"Profile '{name}' imported", timeout=2))
        except (json.JSONDecodeError, OSError):
            self.toast_overlay.add_toast(Adw.Toast(title="Failed to read profile file", timeout=2))
        except GLib.Error:
            pass

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

    def _on_autostart_toggled(self, action, value):
        from tray import enable_autostart, disable_autostart
        enabled = value.get_boolean()
        action.set_state(value)
        if enabled:
            enable_autostart()
        else:
            disable_autostart()
        # Save to profile
        active = self.config.get("active_profile", "default")
        self.config["profiles"][active]["autostart"] = enabled
        save_config(self.config)

    def _on_show_tray_toggled(self, action, value):
        enabled = value.get_boolean()
        action.set_state(value)
        active = self.config.get("active_profile", "default")
        self.config["profiles"][active]["show_tray"] = enabled
        save_config(self.config)
        # Start/stop tray icon at runtime
        app = self.get_application()
        if hasattr(app, "tray_icon"):
            if enabled:
                app.tray_icon.start()
            else:
                app.tray_icon.stop()

    def _on_history(self, *args):
        """Show session history as an in-window page."""
        from datetime import datetime, timezone

        page = Adw.NavigationPage(title="Session History", tag="history")
        toolbar = Adw.ToolbarView()
        page.set_child(toolbar)

        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        toast_overlay = Adw.ToastOverlay()
        toolbar.set_content(toast_overlay)

        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        toast_overlay.set_child(scroll)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        scroll.set_child(box)

        entries = load_history()
        entries.reverse()  # newest first

        if not entries:
            empty = Adw.StatusPage(
                title="No History",
                description="Authentication events will appear here.",
                icon_name="document-open-recent-symbolic",
            )
            box.append(empty)
        else:
            group = Adw.PreferencesGroup(title=f"{len(entries)} Events")
            box.append(group)

            event_labels = {
                "auth_success": ("Authenticated", "emblem-ok-symbolic"),
                "auth_failed": ("Auth Failed", "dialog-error-symbolic"),
                "renew_success": ("Renewed", "view-refresh-symbolic"),
                "renew_failed": ("Renew Failed", "dialog-error-symbolic"),
            }

            for entry in entries:
                event = entry.get("event", "unknown")
                label, icon = event_labels.get(event, (event, "dialog-information-symbolic"))
                profile = entry.get("profile", "")
                detail = entry.get("detail", "")

                try:
                    dt = datetime.fromisoformat(entry.get("time", ""))
                    time_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    time_str = entry.get("time", "?")

                subtitle = time_str
                if profile:
                    subtitle += f" · {profile}"
                if detail:
                    subtitle += f"\n{detail}"

                row = Adw.ActionRow(title=label, subtitle=subtitle)
                row.set_subtitle_lines(0)
                row.add_prefix(Gtk.Image.new_from_icon_name(icon))
                group.add(row)

            # Clear history button
            clear_btn = Gtk.Button(label="Clear History")
            clear_btn.add_css_class("destructive-action")
            clear_btn.add_css_class("pill")
            clear_btn.set_halign(Gtk.Align.CENTER)
            clear_btn.set_margin_top(12)

            def _clear(_btn):
                dialog = Adw.AlertDialog(
                    heading="Clear History?",
                    body="This will delete all session history entries.",
                )
                dialog.add_response("cancel", "Cancel")
                dialog.add_response("clear", "Clear")
                dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
                def _on_response(_dlg, response):
                    if response == "clear":
                        clear_history()
                        self.nav_view.pop()
                        toast_overlay.add_toast(Adw.Toast(title="History cleared", timeout=2))
                dialog.connect("response", _on_response)
                dialog.present(self)

            clear_btn.connect("clicked", _clear)
            box.append(clear_btn)

        self.nav_view.push(page)

    def _on_about(self, *args):
        """Show About info as an in-window page instead of a separate dialog."""
        about_page = Adw.NavigationPage(title="About", tag="about")

        about_toolbar = Adw.ToolbarView()
        about_page.set_child(about_toolbar)

        about_header = Adw.HeaderBar()
        about_toolbar.add_top_bar(about_header)

        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        about_toolbar.set_content(scroll)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        scroll.set_child(box)

        # App icon (use installed icon, fall back to generic)
        icon_path = os.path.join(os.path.dirname(__file__), "icons", "vaultsign-128.png")
        if os.path.isfile(icon_path):
            icon = Gtk.Image.new_from_file(icon_path)
            icon.set_pixel_size(96)
        else:
            icon = Gtk.Image.new_from_icon_name("dialog-password")
            icon.set_pixel_size(96)
        icon.set_halign(Gtk.Align.CENTER)
        box.append(icon)

        # App name
        name_label = Gtk.Label(label="VaultSign")
        name_label.add_css_class("title-1")
        name_label.set_halign(Gtk.Align.CENTER)
        box.append(name_label)

        # Version
        version_label = Gtk.Label(label=f"Version {VERSION}")
        version_label.add_css_class("dim-label")
        version_label.set_halign(Gtk.Align.CENTER)
        box.append(version_label)

        # Description
        desc_label = Gtk.Label(
            label="OIDC Authentication & SSH Key Signing\nfor HashiCorp Vault and OpenBao",
            justify=Gtk.Justification.CENTER,
        )
        desc_label.set_halign(Gtk.Align.CENTER)
        box.append(desc_label)

        # Links group
        links_group = Adw.PreferencesGroup()
        links_group.set_margin_top(8)
        box.append(links_group)

        website_row = Adw.ActionRow(title="Website", subtitle="github.com/dem0n1337/vaultsign")
        website_row.set_activatable(True)
        website_row.add_suffix(Gtk.Image.new_from_icon_name("adw-external-link-symbolic"))
        website_row.connect("activated", lambda _: __import__("webbrowser").open("https://github.com/dem0n1337/vaultsign"))
        links_group.add(website_row)

        issues_row = Adw.ActionRow(title="Report an Issue", subtitle="GitHub Issues")
        issues_row.set_activatable(True)
        issues_row.add_suffix(Gtk.Image.new_from_icon_name("adw-external-link-symbolic"))
        issues_row.connect("activated", lambda _: __import__("webbrowser").open("https://github.com/dem0n1337/vaultsign/issues"))
        links_group.add(issues_row)

        # Credits group
        credits_group = Adw.PreferencesGroup(title="Credits")
        box.append(credits_group)

        dev_row = Adw.ActionRow(title="Developer", subtitle="dem0n1337")
        credits_group.add(dev_row)

        license_row = Adw.ActionRow(title="License", subtitle="MIT")
        credits_group.add(license_row)

        copyright_label = Gtk.Label(label="© 2026 VaultSign Contributors")
        copyright_label.add_css_class("dim-label")
        copyright_label.add_css_class("caption")
        copyright_label.set_halign(Gtk.Align.CENTER)
        copyright_label.set_margin_top(8)
        box.append(copyright_label)

        self.nav_view.push(about_page)

    # --- Session page with countdown ---

    def _push_session_page(self):
        """Push the active session page with animated countdown ring."""
        # Don't push if already on the session page
        visible = self.nav_view.get_visible_page()
        if visible and visible.get_tag() == "session":
            return

        from cert_utils import parse_cert_expiry

        ssh_key = os.path.expanduser(self._collect_config().get("ssh_key_path", ""))
        cert_path = ssh_key + "-cert.pub"
        cert_info = parse_cert_expiry(cert_path)
        token_info = check_token_status(self._collect_config())

        # Determine total TTL and what's remaining
        if cert_info and not cert_info["is_expired"]:
            total_seconds = max(
                (cert_info["valid_to"] - cert_info["valid_from"]).total_seconds(), 1
            )
            self._session_start_remaining = cert_info["remaining_seconds"]
        elif token_info and token_info["ttl"] > 0:
            total_seconds = token_info["ttl"] * 2  # estimate: assume half expired
            self._session_start_remaining = token_info["ttl"]
        else:
            return  # Nothing to show

        self._session_total = total_seconds
        self._session_timer_id = None

        # Build the page
        session_page = Adw.NavigationPage(title="Active Session", tag="session")
        session_toolbar = Adw.ToolbarView()
        session_page.set_child(session_toolbar)

        session_header = Adw.HeaderBar()
        session_toolbar.add_top_bar(session_header)

        session_toast = Adw.ToastOverlay()
        session_toolbar.set_content(session_toast)

        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        session_toast.set_child(scroll)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_halign(Gtk.Align.CENTER)
        scroll.set_child(box)

        # Countdown ring (Cairo drawing area) with labels overlaid inside
        ring_size = 200
        drawing_area = Gtk.DrawingArea()
        drawing_area.set_content_width(ring_size)
        drawing_area.set_content_height(ring_size)

        # Overlay: labels centered inside the ring
        ring_overlay = Gtk.Overlay()
        ring_overlay.set_child(drawing_area)
        ring_overlay.set_halign(Gtk.Align.CENTER)

        label_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        label_box.set_halign(Gtk.Align.CENTER)
        label_box.set_valign(Gtk.Align.CENTER)

        time_label = Gtk.Label()
        time_label.add_css_class("title-1")
        time_label.set_halign(Gtk.Align.CENTER)
        label_box.append(time_label)

        status_label = Gtk.Label()
        status_label.add_css_class("dim-label")
        status_label.set_halign(Gtk.Align.CENTER)
        label_box.append(status_label)

        ring_overlay.add_overlay(label_box)
        box.append(ring_overlay)

        # Details group
        details_group = Adw.PreferencesGroup(title="Session Details")
        details_group.set_margin_top(12)
        box.append(details_group)

        def _add_detail_row(group, title, subtitle):
            """Add a detail row with wrapping subtitle and copy button."""
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            row.set_subtitle_lines(3)
            copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
            copy_btn.set_valign(Gtk.Align.CENTER)
            copy_btn.add_css_class("flat")
            copy_btn.set_tooltip_text(f"Copy {title}")
            def _copy(_b, text=subtitle):
                self._clipboard_set_with_autoclear(text)
                session_toast.add_toast(Adw.Toast(title=f"{title} copied", timeout=2))
            copy_btn.connect("clicked", _copy)
            row.add_suffix(copy_btn)
            group.add(row)

        if cert_info:
            if cert_info.get("key_id"):
                _add_detail_row(details_group, "Key ID", cert_info["key_id"])
            if cert_info.get("principals"):
                _add_detail_row(details_group, "Principals", ", ".join(cert_info["principals"]))
            _add_detail_row(details_group, "Valid Until",
                cert_info["valid_to"].strftime("%Y-%m-%d %H:%M:%S %Z"))

        if token_info:
            _add_detail_row(details_group, "Token", token_info.get("display_name", "unknown"))
            if token_info.get("policies"):
                _add_detail_row(details_group, "Policies", ", ".join(token_info["policies"]))

        # Button area
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_halign(Gtk.Align.CENTER)
        btn_box.set_margin_top(12)
        box.append(btn_box)

        # Quick re-sign button (only if token is valid — skips OIDC)
        if token_info and token_info["ttl"] > 0:
            from vault_backend import sign_ssh_key, add_to_ssh_agent

            renew_btn = Gtk.Button(label="Renew Certificate")
            renew_btn.add_css_class("suggested-action")
            renew_btn.add_css_class("pill")

            def _renew(_btn):
                _btn.set_sensitive(False)
                config = self._collect_config()

                def _worker():
                    ok1, out1 = sign_ssh_key(config)
                    ok2, out2 = add_to_ssh_agent(config) if ok1 else (False, "")

                    def _done():
                        _btn.set_sensitive(True)
                        profile_name = self.config.get("active_profile", "default")
                        if ok1 and ok2:
                            session_toast.add_toast(Adw.Toast(title="Certificate renewed", timeout=2))
                            self.nav_view.pop()
                            GLib.timeout_add(300, self._push_session_page)
                            append_history("renew_success", profile_name)
                        else:
                            msg = (out1 + "\n" + out2).strip().split("\n")[0][:80]
                            session_toast.add_toast(Adw.Toast(title=f"Renew failed: {msg}", timeout=2))
                            append_history("renew_failed", profile_name, msg)
                        return False

                    GLib.idle_add(_done)

                threading.Thread(target=_worker, daemon=True).start()

            renew_btn.connect("clicked", _renew)
            btn_box.append(renew_btn)

        # Re-authenticate button (with confirmation — full OIDC flow)
        reauth_btn = Gtk.Button(label="Re-authenticate")
        reauth_btn.add_css_class("flat")
        reauth_btn.add_css_class("pill")

        def _reauth(_btn):
            dialog = Adw.AlertDialog(
                heading="Re-authenticate?",
                body="This will start a new OIDC login flow.",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("reauth", "Re-authenticate")
            dialog.set_response_appearance("reauth", Adw.ResponseAppearance.SUGGESTED)
            def _on_response(_dlg, response):
                if response == "reauth":
                    self.nav_view.pop()
                    GLib.idle_add(lambda: self._on_authenticate(None) or False)
            dialog.connect("response", _on_response)
            dialog.present(self)

        reauth_btn.connect("clicked", _reauth)
        btn_box.append(reauth_btn)

        # SSH Agent keys section
        agent_group = Adw.PreferencesGroup(title="SSH Agent")
        agent_group.set_margin_top(12)
        box.append(agent_group)

        def _refresh_agent_keys():
            # Remove existing rows
            while True:
                child = agent_group.get_first_child()
                # Skip the group's internal header
                if child is None:
                    break
                # PreferencesGroup wraps children in a listbox; iterate via the group
                break
            # Clear by removing all rows we added
            for old_row in list(getattr(agent_group, '_key_rows', [])):
                agent_group.remove(old_row)
            agent_group._key_rows = []

            keys = list_agent_keys()
            configured_key = os.path.expanduser(self._collect_config().get("ssh_key_path", ""))
            configured_fp = get_key_fingerprint(configured_key + ".pub")

            if not keys:
                empty_row = Adw.ActionRow(title="No keys loaded", subtitle="ssh-agent has no identities")
                empty_row.set_sensitive(False)
                agent_group.add(empty_row)
                agent_group._key_rows = [empty_row]
                return

            for key in keys:
                comment = key.get("comment", "")
                fp = key.get("fingerprint", "")
                bits = key.get("bits", "")
                ktype = key.get("type", "")

                title = comment if comment else fp
                subtitle_parts = []
                if ktype:
                    subtitle_parts.append(ktype)
                if bits:
                    subtitle_parts.append(f"{bits} bits")
                subtitle_parts.append(fp)

                row = Adw.ActionRow(title=title, subtitle=" · ".join(subtitle_parts))
                row.set_subtitle_lines(0)

                # Highlight if this is the configured key
                is_configured = (configured_fp and fp == configured_fp) or (
                    comment and (
                        os.path.normpath(comment) == os.path.normpath(configured_key)
                        or os.path.normpath(comment) == os.path.normpath(configured_key + "-cert.pub")
                    )
                )
                if is_configured:
                    icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                    icon.set_tooltip_text("Configured key")
                    row.add_prefix(icon)

                # Copy fingerprint button
                copy_fp_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
                copy_fp_btn.set_valign(Gtk.Align.CENTER)
                copy_fp_btn.add_css_class("flat")
                copy_fp_btn.set_tooltip_text("Copy fingerprint")
                def _copy_fp(_b, key_fp=fp):
                    self._clipboard_set_with_autoclear(key_fp)
                    session_toast.add_toast(Adw.Toast(title="Fingerprint copied", timeout=2))
                copy_fp_btn.connect("clicked", _copy_fp)
                row.add_suffix(copy_fp_btn)

                agent_group.add(row)
                agent_group._key_rows = getattr(agent_group, '_key_rows', []) + [row]

        _refresh_agent_keys()

        # Draw function for the countdown ring
        import time as _time

        def _draw_ring(area, cr, width, height):
            cx, cy = width / 2, height / 2
            radius = min(width, height) / 2 - 12
            line_width = 10

            # Recalculate remaining from cert (live)
            fresh_info = parse_cert_expiry(cert_path)
            if fresh_info and not fresh_info["is_expired"]:
                remaining = fresh_info["remaining_seconds"]
            elif token_info and token_info["ttl"] > 0:
                remaining = max(0, self._session_start_remaining - (self._session_elapsed or 0))
            else:
                remaining = 0

            fraction = max(0.0, min(1.0, remaining / self._session_total))

            # Background track (dark gray)
            cr.set_line_width(line_width)
            cr.set_source_rgba(0.3, 0.3, 0.3, 0.3)
            cr.arc(cx, cy, radius, 0, 2 * math.pi)
            cr.stroke()

            # Color based on absolute time remaining
            if remaining < 1800:
                r, g, b = 0.9, 0.2, 0.2
            elif remaining < 7200:
                r, g, b = 0.95, 0.75, 0.1
            else:
                r, g, b = 0.2, 0.8, 0.4

            # Pulse glow when expiring soon (<15 min)
            is_urgent = 0 < remaining < 900
            if is_urgent:
                pulse = 0.5 + 0.5 * math.sin(_time.time() * 3.0)  # ~0.5 Hz oscillation
                glow_alpha = 0.15 * pulse
                cr.set_source_rgba(r, g, b, glow_alpha)
                cr.arc(cx, cy, radius + 6, 0, 2 * math.pi)
                cr.set_line_width(line_width + 12)
                cr.stroke()

            # Animated arc (clockwise from top)
            if fraction > 0:
                cr.set_line_width(line_width)
                cr.set_line_cap(1)  # CAIRO_LINE_CAP_ROUND
                arc_alpha = 0.9
                if is_urgent:
                    arc_alpha = 0.6 + 0.4 * (0.5 + 0.5 * math.sin(_time.time() * 3.0))
                cr.set_source_rgba(r, g, b, arc_alpha)
                start_angle = -math.pi / 2
                end_angle = start_angle + 2 * math.pi * fraction
                cr.arc(cx, cy, radius, start_angle, end_angle)
                cr.stroke()

            # Glow dot at the end of the arc
            if fraction > 0:
                dot_angle = start_angle + 2 * math.pi * fraction
                dot_x = cx + radius * math.cos(dot_angle)
                dot_y = cy + radius * math.sin(dot_angle)
                cr.set_source_rgba(r, g, b, 0.5)
                cr.arc(dot_x, dot_y, line_width * 0.8, 0, 2 * math.pi)
                cr.fill()

        drawing_area.set_draw_func(_draw_ring)

        # Timer: update every second
        self._session_elapsed = 0

        def _tick():
            self._session_elapsed += 1

            fresh_info = parse_cert_expiry(cert_path)
            if fresh_info and not fresh_info["is_expired"]:
                remaining = fresh_info["remaining_seconds"]
                time_label.set_text(fresh_info["remaining_human"])
                status_label.set_text("Certificate active")
            else:
                remaining = max(0, self._session_start_remaining - self._session_elapsed)
                from cert_utils import _format_remaining
                time_label.set_text(_format_remaining(remaining))
                if remaining <= 0:
                    status_label.set_text("Session expired")
                else:
                    status_label.set_text("Token active")

            drawing_area.queue_draw()

            if remaining <= 0:
                status_label.set_text("Session expired")
                time_label.add_css_class("error")
                session_toast.add_toast(Adw.Toast(title="Session expired. Please re-authenticate.", timeout=2))
                return False  # Stop timer

            return True  # Keep ticking

        # Initial state
        _tick()
        self._session_elapsed = 0  # Reset after initial tick
        self._session_timer_id = GLib.timeout_add_seconds(1, _tick)

        # Clean up timer when page is popped
        def _on_hidden(*args):
            if self._session_timer_id is not None:
                GLib.source_remove(self._session_timer_id)
                self._session_timer_id = None
            # Refresh session row when returning to main
            self._update_token_status()

        session_page.connect("hidden", _on_hidden)

        self.nav_view.push(session_page)

    # --- Log export ---

    def _on_copy_log(self, _button):
        """Copy log contents to clipboard."""
        start = self.log_buffer.get_start_iter()
        end = self.log_buffer.get_end_iter()
        text = self.log_buffer.get_text(start, end, False).strip()
        if not text:
            self.toast_overlay.add_toast(Adw.Toast(title="No log entries yet", timeout=2))
            return
        self._clipboard_set_with_autoclear(text)
        toast = Adw.Toast(title="Log copied to clipboard", timeout=2)
        self.toast_overlay.add_toast(toast)

    def _on_save_log(self, _button):
        """Save log to a file using file chooser dialog."""
        start = self.log_buffer.get_start_iter()
        end = self.log_buffer.get_end_iter()
        text = self.log_buffer.get_text(start, end, False).strip()
        if not text:
            self.toast_overlay.add_toast(Adw.Toast(title="No log entries yet", timeout=2))
            return
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
                toast = Adw.Toast(title=f"Log saved to {os.path.basename(path)}", timeout=2)
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
        toast = Adw.Toast(title="Settings saved", timeout=2)
        self.toast_overlay.add_toast(toast)

    def _on_cancel(self, _button):
        """Request cancellation of the running auth flow."""
        request_cancel()
        self.cancel_button.set_sensitive(False)

    def _show_first_run_wizard(self):
        self.set_visible(False)
        cli_info = detect_cli()

        wizard = Adw.Window(application=self.get_application())
        wizard.set_title("VaultSign Setup")
        wizard.set_default_size(460, 540)
        wizard.set_resizable(False)

        toolbar_view = Adw.ToolbarView()
        wizard.set_content(toolbar_view)
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        header.set_show_start_title_buttons(False)
        toolbar_view.add_top_bar(header)

        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT)
        toolbar_view.set_content(stack)

        wizard_state = {"cli_path": cli_info.get("vault_path") or cli_info.get("bao_path") or ""}
        wizard_closed = [False]

        def _finish_wizard(save: bool):
            if wizard_closed[0]:
                return
            wizard_closed[0] = True
            if save:
                self.vault_addr_row.set_text(addr_entry.get_text())
                self.vault_cli_row.set_text(cli_entry.get_text())
                self.ssh_key_row.set_text(key_entry.get_text())
                role = role_entry.get_text().strip()
                if role:
                    self.role_row.set_text(role)
                self._on_save_settings(None)
            wizard.destroy()
            self.set_visible(True)
            self.present()

        # --- PAGE 1: CLI Detection ---
        cli_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        cli_page.set_margin_top(24)
        cli_page.set_margin_bottom(24)
        cli_page.set_margin_start(24)
        cli_page.set_margin_end(24)

        cli_title = Gtk.Label(label="Welcome to VaultSign")
        cli_title.add_css_class("title-1")
        cli_page.append(cli_title)

        if cli_info["detected"]:
            found_name = "HashiCorp Vault" if cli_info["detected"] == "vault" else "OpenBao"
            found_path = cli_info["vault_path"] or cli_info["bao_path"]
            cli_status = Gtk.Label(label=f"{found_name} CLI detected at:\n{found_path}")
            cli_status.set_justify(Gtk.Justification.CENTER)
            cli_status.add_css_class("dim-label")
            cli_page.append(cli_status)

            cli_ok_icon = Gtk.Image.new_from_icon_name("object-select-symbolic")
            cli_ok_icon.set_pixel_size(64)
            cli_ok_icon.set_opacity(0.6)
            cli_page.append(cli_ok_icon)

            continue_btn = Gtk.Button(label="Continue")
            continue_btn.add_css_class("suggested-action")
            continue_btn.add_css_class("pill")
            continue_btn.connect("clicked", lambda _: stack.set_visible_child_name("config"))
            cli_page.append(continue_btn)
        else:
            cli_desc = Gtk.Label(
                label="No Vault-compatible CLI was found.\nVaultSign requires HashiCorp Vault or OpenBao CLI.",
            )
            cli_desc.set_justify(Gtk.Justification.CENTER)
            cli_desc.add_css_class("dim-label")
            cli_desc.set_wrap(True)
            cli_page.append(cli_desc)

            warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            warn_icon.set_pixel_size(48)
            cli_page.append(warn_icon)

            install_status = Gtk.Label(label="")
            install_status.set_wrap(True)
            install_status.set_visible(False)
            cli_page.append(install_status)

            pkg_mgr = cli_info["pkg_manager"]

            def _do_install(product: str, button: Gtk.Button):
                if not pkg_mgr:
                    install_status.set_text("No supported package manager found.")
                    install_status.set_visible(True)
                    return
                button.set_sensitive(False)
                install_status.set_text(f"Installing {product}...")
                install_status.set_visible(True)

                def _install_thread():
                    ok, output = install_cli(product, pkg_mgr)
                    def _update():
                        button.set_sensitive(True)
                        if ok:
                            new_info = detect_cli()
                            wizard_state["cli_path"] = new_info.get("vault_path") or new_info.get("bao_path") or ""
                            install_status.set_text("Installation successful!")
                            cli_entry.set_text(wizard_state["cli_path"])
                            GLib.timeout_add(800, lambda: stack.set_visible_child_name("config") or False)
                        else:
                            install_status.set_text(f"Failed: {output[:200]}")
                        return False
                    GLib.idle_add(_update)

                threading.Thread(target=_install_thread, daemon=True).start()

            install_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            cli_page.append(install_box)
            pkg_label = f"via {pkg_mgr}" if pkg_mgr else "(no package manager detected)"

            vault_btn = Gtk.Button(label=f"Install HashiCorp Vault  ({pkg_label})")
            vault_btn.add_css_class("suggested-action")
            vault_btn.add_css_class("pill")
            if not pkg_mgr:
                vault_btn.set_sensitive(False)
            vault_btn.connect("clicked", lambda b: _do_install("vault", b))
            install_box.append(vault_btn)

            bao_btn = Gtk.Button(label=f"Install OpenBao  ({pkg_label})")
            bao_btn.add_css_class("pill")
            if not pkg_mgr:
                bao_btn.set_sensitive(False)
            bao_btn.connect("clicked", lambda b: _do_install("openbao", b))
            install_box.append(bao_btn)

            skip_install = Gtk.Button(label="Skip - I'll configure it manually")
            skip_install.add_css_class("flat")
            skip_install.add_css_class("pill")
            skip_install.set_margin_top(8)
            skip_install.connect("clicked", lambda _: stack.set_visible_child_name("config"))
            cli_page.append(skip_install)

        stack.add_named(cli_page, "cli")

        # --- PAGE 2: Configuration ---
        config_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        config_page.set_margin_top(24)
        config_page.set_margin_bottom(24)
        config_page.set_margin_start(24)
        config_page.set_margin_end(24)

        config_title = Gtk.Label(label="Configure Connection")
        config_title.add_css_class("title-1")
        config_page.append(config_title)

        config_desc = Gtk.Label(label="You can change these settings later.")
        config_desc.add_css_class("dim-label")
        config_page.append(config_desc)

        settings_group = Adw.PreferencesGroup()
        config_page.append(settings_group)

        addr_entry = Adw.EntryRow(title="Server Address")
        addr_entry.set_text(self.profile.get("vault_addr", ""))
        settings_group.add(addr_entry)

        cli_entry = Adw.EntryRow(title="CLI Path (vault / bao)")
        cli_entry.set_text(wizard_state["cli_path"] or shutil.which("vault") or self.profile.get("vault_cli_path", ""))
        settings_group.add(cli_entry)

        key_entry = Adw.EntryRow(title="SSH Key Path")
        key_entry.set_text(self.profile.get("ssh_key_path", ""))
        settings_group.add(key_entry)

        role_entry = Adw.EntryRow(title="Default Role")
        role_entry.set_text(self.profile.get("role", ""))
        settings_group.add(role_entry)

        config_btn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        config_btn_box.set_margin_top(8)
        config_page.append(config_btn_box)

        save_btn = Gtk.Button(label="Save & Continue")
        save_btn.add_css_class("suggested-action")
        save_btn.add_css_class("pill")
        save_btn.connect("clicked", lambda _: _finish_wizard(True))
        config_btn_box.append(save_btn)

        back_btn = Gtk.Button(label="Back")
        back_btn.add_css_class("flat")
        back_btn.add_css_class("pill")
        back_btn.connect("clicked", lambda _: stack.set_visible_child_name("cli"))
        config_btn_box.append(back_btn)

        skip_btn = Gtk.Button(label="Skip")
        skip_btn.add_css_class("flat")
        skip_btn.add_css_class("pill")
        skip_btn.connect("clicked", lambda _: _finish_wizard(False))
        config_btn_box.append(skip_btn)

        stack.add_named(config_page, "config")
        stack.set_visible_child_name("cli")

        wizard.connect("close-request", lambda _: (_finish_wizard(False), True)[1])
        wizard.present()
        return False

    def _on_authenticate(self, _button):
        """Validate, save, and run auth in a background thread."""
        self._on_save_settings(None)
        config = self._collect_config()

        missing = []
        if not config.get("vault_addr"):
            missing.append("Server Address")
        if not config.get("role"):
            missing.append("Role")
        if not config.get("ssh_key_path"):
            missing.append("SSH Key Path")
        if missing:
            self.toast_overlay.add_toast(Adw.Toast(title=f"Missing: {', '.join(missing)}", timeout=3))
            return

        vault_addr = config["vault_addr"].lower()
        if vault_addr.startswith("http://") and "localhost" not in vault_addr and "127.0.0.1" not in vault_addr:
            self._append_log("WARNING: Server address does not use HTTPS.")

        reset_cancel()

        # Disable button and clear log
        self.auth_button.set_sensitive(False)
        self.cancel_button.set_sensitive(True)
        self.log_buffer.set_text("")
        self.toast_overlay.add_toast(Adw.Toast(title="Authenticating\u2026", timeout=2))

        def step_callback(step_name: str, success: bool, output: str) -> None:
            """Called from worker thread after each step completes."""
            output = redact_tokens(output) if output else output
            status = "OK" if success else "FAILED"
            label = _STEP_LABELS.get(step_name, step_name)

            def _update_ui():
                self._append_log(f"[{step_name}] {status}")
                if output:
                    self._append_log(output)
                self.toast_overlay.add_toast(Adw.Toast(title=label, timeout=2))
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
                profile_name = self.config.get("active_profile", "default")
                if success:
                    self.toast_overlay.add_toast(Adw.Toast(title="Authentication successful.", timeout=2))
                    self._update_token_status()
                    GLib.timeout_add(500, self._push_session_page)
                    append_history("auth_success", profile_name)
                else:
                    first_line = output.split("\n")[0][:80]
                    self.toast_overlay.add_toast(Adw.Toast(title=f"Error: {first_line}", timeout=2))
                    append_history("auth_failed", profile_name, first_line)
                return False

            GLib.idle_add(_finish)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()


class VaultSignApp(Adw.Application):
    """Application entry point."""

    def __init__(self, start_minimized=False):
        super().__init__(application_id="io.github.dem0n1337.vaultsign")
        self._win = None
        self._start_minimized = start_minimized

    def do_activate(self):
        # Re-present existing window if already created (e.g. activated from notification)
        if self._win is not None:
            self._win.present()
            return

        win = VaultSignWindow(application=self)
        self._win = win

        # Hide on close instead of destroying — keeps app alive in background
        def _on_close_request(_win):
            _win.set_visible(False)
            return True  # Prevent destruction

        win.connect("close-request", _on_close_request)

        # Keep the application alive even when the window is hidden
        self.hold()

        # Add a quit action so users can fully exit from the menu
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)

        # Re-auth action (triggered from notification button)
        reauth_action = Gio.SimpleAction.new("reauth", None)
        def _on_reauth(*_args):
            win.present()
            GLib.idle_add(lambda: win._on_authenticate(None) or False)
        reauth_action.connect("activate", _on_reauth)
        self.add_action(reauth_action)

        if not self._start_minimized:
            win.present()

        from tray import ExpiryMonitor, TrayIcon, enable_autostart, disable_autostart
        from cert_utils import parse_cert_expiry

        def get_cert_info():
            profile = get_active_profile(win.config)
            ssh_key = os.path.expanduser(profile.get("ssh_key_path", ""))
            return parse_cert_expiry(ssh_key + "-cert.pub")

        def get_active_config():
            return get_active_profile(win.config)

        profile = get_active_profile(win.config)
        self.expiry_monitor = ExpiryMonitor(self, get_active_config, get_cert_info)
        if profile.get("show_tray", True):
            self.expiry_monitor.start()

        # System tray icon
        self.tray_icon = TrayIcon(self, get_cert_info)
        if profile.get("show_tray", True) and TrayIcon.is_available():
            self.tray_icon.start()

        # Autostart
        if profile.get("autostart", True):
            enable_autostart()
        else:
            disable_autostart()

        import webbrowser
        from updater import check_for_update

        def _check_update():
            update_info = check_for_update()
            if update_info:
                def _notify():
                    toast = Adw.Toast(title=f"VaultSign {update_info['version']} available", timeout=2)
                    toast.set_button_label("Details")
                    toast.connect("button-clicked", lambda _: webbrowser.open(update_info["url"]))
                    win.toast_overlay.add_toast(toast)
                    return False
                GLib.idle_add(_notify)

        threading.Thread(target=_check_update, daemon=True).start()


def main():
    import argparse
    import resource

    parser = argparse.ArgumentParser(description="VaultSign — OIDC Auth & SSH Key Signing")
    parser.add_argument("--minimize", "-m", action="store_true",
                        help="Start minimized to tray (no window)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable GTK Inspector and verbose logging")
    args, remaining = parser.parse_known_args()

    if args.debug:
        os.environ["GTK_DEBUG"] = "interactive"

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error):
        pass

    app = VaultSignApp(start_minimized=args.minimize)
    app.run(remaining)


if __name__ == "__main__":
    main()
