"""
gui/dashboard.py
Dashboard widget — Fluent Design inspired dashboard view showing server stats and scan launch triggers.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout, QSizePolicy, QSpacerItem,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont

from gui.styles import get_severity_color, get_risk_color
from core import database as db


class StatCard(QFrame):
    """A clean Fluent-style stat card showing a value and label."""

    def __init__(self, label: str, value: str = "0", color: str = "#0078d4",
                 parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("cardFrame")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.setSpacing(2)
        layout.setContentsMargins(16, 12, 16, 12)

        self._label = QLabel(label)
        self._label.setStyleSheet("color: #737373; background: transparent; font-size: 11px; font-weight: 600; text-transform: uppercase;")
        self._label.setAlignment(Qt.AlignLeft)

        self._value_label = QLabel(value)
        self._value_label.setFont(QFont("Segoe UI Variable Text", 20, QFont.Bold))
        self._value_label.setStyleSheet(f"color: {color}; background: transparent;")
        self._value_label.setAlignment(Qt.AlignLeft)

        layout.addWidget(self._label)
        layout.addWidget(self._value_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(str(value))

    def set_color(self, color: str) -> None:
        self._value_label.setStyleSheet(f"color: {color}; background: transparent;")


class DashboardWidget(QWidget):
    """Main dashboard page following Windows 11 design guidelines."""

    request_quick_scan = Signal()
    request_full_scan = Signal()
    request_resource_scan = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh_stats)
        self._refresh_timer.start(5000)
        self.refresh_stats()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(32, 28, 32, 28)

        # ── Header ────────────────────────────────────────────────────────
        header_layout = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(4)

        title = QLabel("Security Dashboard")
        title.setObjectName("labelTitle")
        title.setFont(QFont("Segoe UI Variable Text", 22, QFont.Bold))

        subtitle = QLabel("Static security analysis for FiveM resource files")
        subtitle.setObjectName("labelSubtitle")
        subtitle.setFont(QFont("Segoe UI Variable Text", 13))

        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col)
        header_layout.addStretch()

        self._status_badge = QLabel("READY")
        self._status_badge.setStyleSheet(
            "color: #22863a; font-size: 11px; font-weight: 700; background: transparent; letter-spacing: 0.05em;"
        )
        header_layout.addWidget(self._status_badge)

        layout.addLayout(header_layout)

        # ── Separator ─────────────────────────────────────────────────────
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # ── Stat cards ────────────────────────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(12)

        # Read current theme to load appropriate colors
        theme = db.get_setting("theme", "Dark")
        dark = (theme == "Dark")
        acc = "#60cdff" if dark else "#0078d4"
        accent_color = "#60cdff" if dark else "#0078d4"

        self._card_resources = StatCard("Resources", "0", accent_color)
        self._card_files = StatCard("Files Scanned", "0", accent_color)
        self._card_threats = StatCard("Total Threats", "0", get_severity_color("CRITICAL", dark))
        self._card_critical = StatCard("Critical Threats", "0", get_severity_color("CRITICAL", dark))
        self._card_high = StatCard("High Threats", "0", get_severity_color("HIGH", dark))
        self._card_medium = StatCard("Medium Threats", "0", get_severity_color("MEDIUM", dark))
        self._card_low = StatCard("Low Threats", "0", get_severity_color("LOW", dark))
        self._card_clean = StatCard("Clean Resources", "0", get_severity_color("SAFE", dark))

        grid.addWidget(self._card_resources, 0, 0)
        grid.addWidget(self._card_files, 0, 1)
        grid.addWidget(self._card_threats, 0, 2)
        grid.addWidget(self._card_critical, 0, 3)
        grid.addWidget(self._card_high, 1, 0)
        grid.addWidget(self._card_medium, 1, 1)
        grid.addWidget(self._card_low, 1, 2)
        grid.addWidget(self._card_clean, 1, 3)

        layout.addLayout(grid)

        # ── Last scan info ────────────────────────────────────────────────
        self._last_scan_card = QFrame()
        self._last_scan_card.setObjectName("cardFrame")
        last_layout = QHBoxLayout(self._last_scan_card)
        last_layout.setContentsMargins(16, 12, 16, 12)

        last_label = QLabel("Last scan:")
        last_label.setStyleSheet("color: #737373; font-weight: 600; background: transparent; font-size: 12px;")

        self._last_scan_text = QLabel("No scans performed yet")
        self._last_scan_text.setStyleSheet("background: transparent; font-size: 12px;")

        last_layout.addWidget(last_label)
        last_layout.addWidget(self._last_scan_text)
        last_layout.addStretch()

        self._overall_risk_label = QLabel("Overall Risk: Unknown")
        self._overall_risk_label.setStyleSheet("font-weight: 600; background: transparent;")
        last_layout.addWidget(self._overall_risk_label)

        layout.addWidget(self._last_scan_card)

        # ── Scan buttons ──────────────────────────────────────────────────
        scan_section = QLabel("Scanning Actions")
        scan_section.setObjectName("labelSectionHeader")
        scan_section.setFont(QFont("Segoe UI Variable Text", 14, QFont.Bold))
        layout.addWidget(scan_section)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self._btn_quick = QPushButton("Quick Scan")
        self._btn_quick.setObjectName("btnPrimary")
        self._btn_quick.setMinimumHeight(40)
        self._btn_quick.clicked.connect(self.request_quick_scan)

        self._btn_full = QPushButton("Full Scan")
        self._btn_full.setObjectName("btnPrimary")
        self._btn_full.setMinimumHeight(40)
        self._btn_full.clicked.connect(self.request_full_scan)

        self._btn_resource = QPushButton("Scan Single Resource...")
        self._btn_resource.setMinimumHeight(40)
        self._btn_resource.clicked.connect(self.request_resource_scan)

        self._btn_clear = QPushButton("Clear Current Scan")
        self._btn_clear.setObjectName("btnDanger")
        self._btn_clear.setMinimumHeight(40)
        self._btn_clear.clicked.connect(self._clear_scan_clicked)

        btn_row.addWidget(self._btn_quick)
        btn_row.addWidget(self._btn_full)
        btn_row.addWidget(self._btn_resource)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()

        layout.addLayout(btn_row)

        # ── Recent activity ───────────────────────────────────────────────
        activity_label = QLabel("Recent Activity")
        activity_label.setObjectName("labelSectionHeader")
        activity_label.setFont(QFont("Segoe UI Variable Text", 14, QFont.Bold))
        layout.addWidget(activity_label)

        self._recent_frame = QFrame()
        self._recent_frame.setObjectName("cardFrame")
        self._recent_layout = QVBoxLayout(self._recent_frame)
        self._recent_layout.setContentsMargins(16, 12, 16, 12)
        self._recent_layout.setSpacing(6)

        self._no_scans_label = QLabel("No scans recorded.")
        self._no_scans_label.setStyleSheet("color: #737373; background: transparent; font-size: 12px;")
        self._no_scans_label.setAlignment(Qt.AlignCenter)
        self._recent_layout.addWidget(self._no_scans_label)

        layout.addWidget(self._recent_frame)
        layout.addStretch()

    def refresh_stats(self) -> None:
        try:
            resources = db.get_all_resources()
            detection_summary = db.get_detection_summary()
            recent_scans = db.get_recent_scans(5)

            theme = db.get_setting("theme", "Dark")
            dark = (theme == "Dark")
            accent_color = "#60cdff" if dark else "#0078d4"

            total_resources = len(resources)
            total_files = sum(r.get("total_files", 0) for r in resources)
            total_detections = detection_summary.get("total", 0)
            critical = detection_summary.get("critical", 0)
            high = detection_summary.get("high", 0)
            medium = detection_summary.get("medium", 0)
            low = detection_summary.get("low", 0)
            clean = sum(1 for r in resources if r.get("risk_score", 0) == 0)

            self._card_resources.set_value(str(total_resources))
            self._card_files.set_value(str(total_files))
            self._card_threats.set_value(str(total_detections))
            self._card_critical.set_value(str(critical))
            self._card_high.set_value(str(high))
            self._card_medium.set_value(str(medium))
            self._card_low.set_value(str(low))
            self._card_clean.set_value(str(clean))

            # Refresh colors based on dark/light
            self._card_resources.set_color(accent_color)
            self._card_files.set_color(accent_color)
            self._card_threats.set_color(get_severity_color("CRITICAL", dark))
            self._card_critical.set_color(get_severity_color("CRITICAL", dark))
            self._card_high.set_color(get_severity_color("HIGH", dark))
            self._card_medium.set_color(get_severity_color("MEDIUM", dark))
            self._card_low.set_color(get_severity_color("LOW", dark))
            self._card_clean.set_color(get_severity_color("SAFE", dark))

            # Overall risk
            if resources:
                max_risk = max(r.get("risk_score", 0) for r in resources)
                from core.risk_scorer import get_risk_level
                level = get_risk_level(max_risk)
                color = get_risk_color(level, dark)
                self._overall_risk_label.setText(f"Overall Risk: {level}")
                self._overall_risk_label.setStyleSheet(
                    f"color: {color}; font-weight: 600; background: transparent;"
                )

            # Recent scans list
            while self._recent_layout.count():
                item = self._recent_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            if recent_scans:
                for scan in recent_scans:
                    row = QFrame()
                    row.setStyleSheet("background: transparent;")
                    row_layout = QHBoxLayout(row)
                    row_layout.setContentsMargins(0, 4, 0, 4)
                    row_layout.setSpacing(12)

                    type_badge = QLabel(scan.get("scan_type", "?").upper())
                    type_badge.setStyleSheet(
                        f"background: {'#3e3e3e' if dark else '#e5e5e5'}; color: {accent_color}; "
                        "padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600;"
                    )
                    row_layout.addWidget(type_badge)

                    path_label = QLabel(scan.get("target_path", "N/A")[-70:])
                    path_label.setStyleSheet("background: transparent; font-size: 12px;")
                    row_layout.addWidget(path_label)
                    row_layout.addStretch()

                    det_label = QLabel(f"{scan.get('total_detections', 0)} threats")
                    color = get_severity_color("CRITICAL", dark) if scan.get("critical_count", 0) > 0 else "#737373"
                    det_label.setStyleSheet(f"color: {color}; background: transparent; font-size: 12px; font-weight: 600;")
                    row_layout.addWidget(det_label)

                    date_label = QLabel(str(scan.get("started_at", ""))[:16])
                    date_label.setStyleSheet("color: #737373; background: transparent; font-size: 11px;")
                    row_layout.addWidget(date_label)

                    self._recent_layout.addWidget(row)

                # Last scan text
                if recent_scans:
                    ls = recent_scans[0]
                    self._last_scan_text.setText(
                        f"{ls.get('scan_type','?').upper()} scan — "
                        f"{ls.get('total_resources',0)} resources, "
                        f"{ls.get('total_detections',0)} threats — "
                        f"{str(ls.get('started_at',''))[:16]}"
                    )
            else:
                self._no_scans_label = QLabel("No scans recorded.")
                self._no_scans_label.setStyleSheet(
                    "color: #737373; background: transparent; font-size: 12px;"
                )
                self._no_scans_label.setAlignment(Qt.AlignCenter)
                self._recent_layout.addWidget(self._no_scans_label)

        except Exception:
            pass

    def set_scanning(self, is_scanning: bool) -> None:
        self._btn_quick.setEnabled(not is_scanning)
        self._btn_full.setEnabled(not is_scanning)
        self._btn_resource.setEnabled(not is_scanning)
        if is_scanning:
            self._status_badge.setText("SCANNING")
            self._status_badge.setStyleSheet(
                "color: #d99f38; font-size: 11px; font-weight: 700; background: transparent; letter-spacing: 0.05em;"
            )
        else:
            self._status_badge.setText("READY")
            self._status_badge.setStyleSheet(
                "color: #22863a; font-size: 11px; font-weight: 700; background: transparent; letter-spacing: 0.05em;"
            )

    def refresh(self) -> None:
        self.refresh_stats()

    def _clear_scan_clicked(self) -> None:
        db.clear_active_scan_data()
        self.refresh_stats()
        self._last_scan_text.setText("Scan results cleared")
        self._overall_risk_label.setText("Overall Risk: Unknown")
        self._overall_risk_label.setStyleSheet("color: #737373; font-weight: 600; background: transparent;")

