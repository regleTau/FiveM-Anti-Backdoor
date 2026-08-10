"""
gui/settings_widget.py
Settings page — Windows 11 Fluent style settings sections.
Configures Scanning, Security, Appearance, and displays About info.
"""

import os
import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QFrame, QFileDialog, QMessageBox,
    QPlainTextEdit, QComboBox, QGroupBox, QScrollArea,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from core import database as db


class SettingsWidget(QWidget):
    """Configuration settings page following Windows 11 Fluent Design guidelines."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()
        self._load_settings()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Settings")
        title.setObjectName("labelTitle")
        title.setFont(QFont("Segoe UI Variable Text", 20, QFont.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        main_layout.addLayout(hdr)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        main_layout.addWidget(sep)

        # Scrollable container for Fluent style settings layout
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(container)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 0, 16, 0)

        # ── 1. Scanning Options ──
        grp_scan = QGroupBox("Scanning Options")
        scan_layout = QVBoxLayout(grp_scan)
        scan_layout.setSpacing(10)
        scan_layout.setContentsMargins(16, 16, 16, 16)

        self._chk_lua = QCheckBox("Scan Lua Resources")
        self._chk_js = QCheckBox("Scan JavaScript Resources")
        self._chk_nui = QCheckBox("Scan NUI Files")
        self._chk_hidden = QCheckBox("Scan Hidden Files")

        scan_layout.addWidget(self._chk_lua)
        scan_layout.addWidget(self._chk_js)
        scan_layout.addWidget(self._chk_nui)
        scan_layout.addWidget(self._chk_hidden)

        # Real-time options
        self._chk_monitor = QCheckBox("Enable Real-time Folder Monitor")
        self._chk_obfuscation = QCheckBox("Enable Obfuscation Checking")
        self._chk_change = QCheckBox("Enable SHA-256 Change Detection")

        scan_layout.addWidget(self._chk_monitor)
        scan_layout.addWidget(self._chk_obfuscation)
        scan_layout.addWidget(self._chk_change)

        layout.addWidget(grp_scan)

        # ── 2. Security Options ──
        grp_sec = QGroupBox("Security Options")
        sec_layout = QVBoxLayout(grp_sec)
        sec_layout.setSpacing(10)
        sec_layout.setContentsMargins(16, 16, 16, 16)

        self._chk_backup = QCheckBox("Automatic backup before cleaning")
        self._chk_quarantine = QCheckBox("Quarantine suspicious files automatically")
        self._chk_confirm = QCheckBox("Request safe removal confirmation")

        sec_layout.addWidget(self._chk_backup)
        sec_layout.addWidget(self._chk_quarantine)
        sec_layout.addWidget(self._chk_confirm)

        layout.addWidget(grp_sec)

        # ── 3. Whitelisted Domains ──
        grp_whitelist = QGroupBox("Whitelisted Domains")
        white_layout = QVBoxLayout(grp_whitelist)
        white_layout.setSpacing(8)
        white_layout.setContentsMargins(16, 16, 16, 16)

        lbl_desc = QLabel("Enter domains to whitelist (one per line):")
        lbl_desc.setStyleSheet("color: #737373;")
        self._txt_whitelist = QPlainTextEdit()
        self._txt_whitelist.setMinimumHeight(80)
        self._txt_whitelist.setMaximumHeight(120)
        
        white_layout.addWidget(lbl_desc)
        white_layout.addWidget(self._txt_whitelist)
        layout.addWidget(grp_whitelist)

        # ── 4. Appearance Options ──
        grp_app = QGroupBox("Appearance Options")
        app_layout = QVBoxLayout(grp_app)
        app_layout.setSpacing(12)
        app_layout.setContentsMargins(16, 16, 16, 16)

        theme_layout = QHBoxLayout()
        theme_lbl = QLabel("App Theme:")
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(["Dark", "Light"])
        theme_layout.addWidget(theme_lbl)
        theme_layout.addWidget(self._theme_combo)
        theme_layout.addStretch()
        app_layout.addLayout(theme_layout)

        accent_layout = QHBoxLayout()
        accent_lbl = QLabel("Accent Color:")
        self._accent_val = QLabel("Standard Windows Blue (#0078d4)")
        self._accent_val.setStyleSheet("color: #0078d4; font-weight: bold;")
        accent_layout.addWidget(accent_lbl)
        accent_layout.addWidget(self._accent_val)
        accent_layout.addStretch()
        app_layout.addLayout(accent_layout)

        layout.addWidget(grp_app)

        # ── 5. About Section ──
        grp_about = QGroupBox("About")
        about_layout = QVBoxLayout(grp_about)
        about_layout.setSpacing(6)
        about_layout.setContentsMargins(16, 16, 16, 16)

        about_layout.addWidget(QLabel("<b>Application Version:</b> 1.0.0"))
        about_layout.addWidget(QLabel("<b>Scanner Engine Version:</b> 1.0.0"))
        about_layout.addWidget(QLabel("<b>Signature Database Version:</b> 1.0.0"))
        about_layout.addWidget(QLabel("<b>Developer:</b> Antigravity Systems"))
        
        layout.addWidget(grp_about)

        # Save Button
        self._btn_save = QPushButton("Save Settings")
        self._btn_save.setObjectName("btnPrimary")
        self._btn_save.setMinimumHeight(38)
        self._btn_save.setMinimumWidth(150)
        self._btn_save.clicked.connect(self._save_settings)
        layout.addWidget(self._btn_save, alignment=Qt.AlignLeft)

        scroll.setWidget(container)
        main_layout.addWidget(scroll, stretch=1)

    def _load_settings(self) -> None:
        try:
            db.init_database()
            self._chk_lua.setChecked(db.get_setting("scan_lua", True))
            self._chk_js.setChecked(db.get_setting("scan_js", True))
            self._chk_nui.setChecked(db.get_setting("scan_nui", True))
            self._chk_hidden.setChecked(db.get_setting("scan_hidden", False))

            self._chk_monitor.setChecked(db.get_setting("monitor_enabled", False))
            self._chk_obfuscation.setChecked(db.get_setting("obfuscation_enabled", True))
            self._chk_change.setChecked(db.get_setting("change_detection_enabled", True))

            self._chk_backup.setChecked(db.get_setting("backup_enabled", True))
            self._chk_quarantine.setChecked(db.get_setting("quarantine_enabled", False))
            self._chk_confirm.setChecked(db.get_setting("confirm_enabled", True))

            theme = db.get_setting("theme", "Dark")
            self._theme_combo.setCurrentText(theme)

            domains = db.get_setting("whitelisted_domains", [
                "github.com", "raw.githubusercontent.com", "cfx.re", "runtime.fivem.net"
            ])
            self._txt_whitelist.setPlainText("\n".join(domains))
        except Exception:
            pass

    def _save_settings(self) -> None:
        try:
            db.set_setting("scan_lua", self._chk_lua.isChecked())
            db.set_setting("scan_js", self._chk_js.isChecked())
            db.set_setting("scan_nui", self._chk_nui.isChecked())
            db.set_setting("scan_hidden", self._chk_hidden.isChecked())

            db.set_setting("monitor_enabled", self._chk_monitor.isChecked())
            db.set_setting("obfuscation_enabled", self._chk_obfuscation.isChecked())
            db.set_setting("change_detection_enabled", self._chk_change.isChecked())

            db.set_setting("backup_enabled", self._chk_backup.isChecked())
            db.set_setting("quarantine_enabled", self._chk_quarantine.isChecked())
            db.set_setting("confirm_enabled", self._chk_confirm.isChecked())

            new_theme = self._theme_combo.currentText()
            db.set_setting("theme", new_theme)

            domains = [
                d.strip() for d in self._txt_whitelist.toPlainText().split("\n") if d.strip()
            ]
            db.set_setting("whitelisted_domains", domains)

            # Apply stylesheet immediately to MainWindow
            parent_window = self.window()
            if hasattr(parent_window, "apply_theme"):
                parent_window.apply_theme(new_theme)

            QMessageBox.information(self, "Settings Saved", "Settings successfully saved and theme applied.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save settings: {e}")
