"""
gui/main_window.py
Main layout and navigation for the FiveM Anti-Backdoor GUI.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QStackedWidget, QLabel, QFrame, QSizePolicy, QMessageBox,
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont, QIcon

from gui.styles import DARK_STYLESHEET
from core import database as db
from gui.dashboard import DashboardWidget
from gui.scanner_widget import ScannerWidget
from gui.resources_widget import ResourcesWidget
from gui.threats_widget import ThreatsWidget
from gui.quarantine_widget import QuarantineWidget
from gui.reports_widget import ReportsWidget
from gui.rules_widget import RulesWidget
from gui.settings_widget import SettingsWidget
from gui.cleaner_dialog import CleanerDialog


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("FiveM Anti-Backdoor & Bad Code Remover")
        self.resize(1200, 800)
        self._monitor = None
        
        # Load theme setting
        theme = db.get_setting("theme", "Dark")
        from gui.styles import DARK_STYLESHEET, LIGHT_STYLESHEET
        self.setStyleSheet(DARK_STYLESHEET if theme == "Dark" else LIGHT_STYLESHEET)

        self._build_ui()
        self._connect_signals()
        self.update_monitor_state()

    def update_monitor_state(self) -> None:
        enabled = db.get_setting("monitor_enabled", False)
        path = db.get_setting("last_scan_directory", "")
        
        if self._monitor:
            try:
                self._monitor.stop()
            except Exception:
                pass
            self._monitor = None

        if enabled and path and os.path.isdir(path):
            from core.monitor import FiveMMonitor
            def on_change(event_type, resource_name, file_path):
                print(f"[MONITOR] File change detected: {event_type} on {resource_name} ({file_path})")
            try:
                self._monitor = FiveMMonitor(path, on_change)
                self._monitor.start()
            except Exception:
                pass

    def apply_theme(self, theme_name: str) -> None:
        from gui.styles import DARK_STYLESHEET, LIGHT_STYLESHEET
        self.setStyleSheet(DARK_STYLESHEET if theme_name == "Dark" else LIGHT_STYLESHEET)
        self.update_monitor_state()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────────
        self._sidebar = QFrame()
        self._sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(self._sidebar)
        sidebar_layout.setContentsMargins(12, 24, 12, 24)
        sidebar_layout.setSpacing(8)

        # Logo / Title
        logo = QLabel("🛡️ FIVEM SEC")
        logo.setFont(QFont("Segoe UI", 16, QFont.Bold))
        logo.setStyleSheet("color: #6c63ff; padding-bottom: 20px; padding-left: 10px; background: transparent;")
        sidebar_layout.addWidget(logo)

        # Nav Buttons
        self._nav_buttons = []
        labels = [
            ("Dashboard", "Dashboard"),
            ("FiveM Scanner", "Scanner"),
            ("Resources", "Resources"),
            ("Threats", "Threats"),
            ("Quarantine", "Quarantine"),
            ("Reports", "Reports"),
            ("Security Rules", "Rules"),
            ("Settings", "Settings"),
        ]

        for text, page_id in labels:
            btn = QPushButton(text)
            btn.setObjectName("navBtn")
            btn.setProperty("page_id", page_id)
            btn.setCheckable(True)
            btn.clicked.connect(self._on_nav_clicked)
            sidebar_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Version label
        ver = QLabel("v1.0.0 (Windows)")
        ver.setStyleSheet("color: #555570; font-size: 10px; padding-left: 10px; background: transparent;")
        sidebar_layout.addWidget(ver)

        main_layout.addWidget(self._sidebar)

        # ── Stacked content ───────────────────────────────────────────────
        self._stack = QStackedWidget()
        
        # Instantiate widgets
        self._dashboard = DashboardWidget()
        self._scanner = ScannerWidget()
        self._resources = ResourcesWidget()
        self._threats = ThreatsWidget()
        self._quarantine = QuarantineWidget()
        self._reports = ReportsWidget()
        self._rules = RulesWidget()
        self._settings = SettingsWidget()

        # Add to stack
        self._stack.addWidget(self._dashboard)      # index 0
        self._stack.addWidget(self._scanner)        # index 1
        self._stack.addWidget(self._resources)      # index 2
        self._stack.addWidget(self._threats)        # index 3
        self._stack.addWidget(self._quarantine)     # index 4
        self._stack.addWidget(self._reports)        # index 5
        self._stack.addWidget(self._rules)          # index 6
        self._stack.addWidget(self._settings)       # index 7

        main_layout.addWidget(self._stack, stretch=1)

        # Default active nav button
        self._set_active_nav("Dashboard")

    def _connect_signals(self) -> None:
        # Dashboard connections
        self._dashboard.request_quick_scan.connect(self._start_quick_scan)
        self._dashboard.request_full_scan.connect(self._start_full_scan)
        self._dashboard.request_resource_scan.connect(self._start_resource_scan)

        # Scanner connections
        self._scanner.scan_finished.connect(self._on_scan_finished)

        # Resource panel connections
        self._resources.request_scan_resource.connect(self._rescan_resource_path)

        # Threat panel connections
        self._threats.request_quarantine.connect(self._quarantine_detection)

    def _set_active_nav(self, page_id: str) -> None:
        # Update check states
        for btn in self._nav_buttons:
            is_active = btn.property("page_id") == page_id
            btn.setChecked(is_active)
            btn.setProperty("active", is_active)
            # Force stylesheet refresh
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _on_nav_clicked(self) -> None:
        sender = self.sender()
        if not sender:
            return
        page_id = sender.property("page_id")
        self._set_active_nav(page_id)

        # Page indexing
        pages = ["Dashboard", "Scanner", "Resources", "Threats", "Quarantine", "Reports", "Rules", "Settings"]
        if page_id in pages:
            idx = pages.index(page_id)
            self._stack.setCurrentIndex(idx)

            # Refresh data on page enter
            widget = self._stack.widget(idx)
            if hasattr(widget, "refresh"):
                widget.refresh()

    def _on_scan_finished(self, results: list) -> None:
        self._dashboard.set_scanning(False)
        self._dashboard.refresh_stats()
        self._reports.set_last_results(results)
        self.update_monitor_state()

    # ── Sidebar signal handlers ───────────────────────────────────────

    def _start_quick_scan(self) -> None:
        # Prompt user to browse if path input empty
        self._stack.setCurrentIndex(1)
        self._set_active_nav("Scanner")
        self._scanner._browse_path()
        self._scanner._type_combo.setCurrentIndex(1) # Quick Scan

    def _start_full_scan(self) -> None:
        self._stack.setCurrentIndex(1)
        self._set_active_nav("Scanner")
        self._scanner._browse_path()
        self._scanner._type_combo.setCurrentIndex(0) # Full Scan

    def _start_resource_scan(self) -> None:
        self._stack.setCurrentIndex(1)
        self._set_active_nav("Scanner")
        self._scanner._browse_path()
        self._scanner._type_combo.setCurrentIndex(2) # Resource Scan

    def _rescan_resource_path(self, path: str) -> None:
        self._stack.setCurrentIndex(1)
        self._set_active_nav("Scanner")
        self._scanner.set_path(path)
        self._scanner._type_combo.setCurrentIndex(2) # Resource Scan

    def _quarantine_detection(self, detection: dict) -> None:
        self._quarantine.quarantine_detection(detection)
        self._stack.setCurrentIndex(4)
        self._set_active_nav("Quarantine")
