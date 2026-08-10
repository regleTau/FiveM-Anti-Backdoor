"""
gui/resources_widget.py
Resources page — lists all scanned FiveM resources with their risk scores.
"""

import os
from typing import List, Dict

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QLineEdit, QSplitter, QTextEdit,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QColor

from core import database as db
from gui.styles import get_risk_color, get_severity_color


class ResourcesWidget(QWidget):
    """Resources list page."""

    request_scan_resource = Signal(str)  # path

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._resources: List[Dict] = []
        self._build_ui()
        self._refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("📦  Resources")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔎 Filter resources...")
        self._search.setMaximumWidth(280)
        self._search.setMinimumHeight(34)
        self._search.textChanged.connect(self._filter_resources)
        hdr.addWidget(self._search)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh)
        hdr.addWidget(refresh_btn)

        layout.addLayout(hdr)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)

        # Resource table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "Resource", "Framework", "Risk Level", "Score", "Files", "Threats"
        ])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self._table.setColumnWidth(1, 100)
        self._table.setColumnWidth(2, 110)
        self._table.setColumnWidth(3, 80)
        self._table.setColumnWidth(4, 70)
        self._table.setColumnWidth(5, 80)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.currentCellChanged.connect(lambda r, c, pr, pc: self._on_row_selected(r))
        splitter.addWidget(self._table)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setObjectName("cardFrame")
        detail_frame.setMinimumWidth(300)
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(10)

        self._detail_title = QLabel("Select a resource")
        self._detail_title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self._detail_title.setStyleSheet("color: #ffffff; background: transparent;")
        detail_layout.addWidget(self._detail_title)

        self._detail_info = QLabel("")
        self._detail_info.setStyleSheet("color: #9090b0; background: transparent; font-size: 12px;")
        self._detail_info.setWordWrap(True)
        detail_layout.addWidget(self._detail_info)

        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.HLine)
        detail_layout.addWidget(sep2)

        det_label = QLabel("Recent Detections")
        det_label.setStyleSheet("color: #6c63ff; font-size: 12px; font-weight: 600; background: transparent;")
        detail_layout.addWidget(det_label)

        self._detail_detections = QTextEdit()
        self._detail_detections.setReadOnly(True)
        self._detail_detections.setFont(QFont("Segoe UI", 11))
        self._detail_detections.setStyleSheet(
            "background: #0d0d1a; border: 1px solid #2d2d4e; border-radius: 6px; color: #c8c8e8;"
        )
        detail_layout.addWidget(self._detail_detections, stretch=1)

        self._scan_btn = QPushButton("Rescan Resource")
        self._scan_btn.setObjectName("btnPrimary")
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._rescan_selected)
        detail_layout.addWidget(self._scan_btn)

        splitter.addWidget(detail_frame)
        splitter.setSizes([600, 340])
        layout.addWidget(splitter, stretch=1)

    def _refresh(self) -> None:
        self._resources = db.get_all_resources()
        self._populate_table(self._resources)

    def _populate_table(self, resources: List[Dict]) -> None:
        self._table.setRowCount(0)
        for res in resources:
            row = self._table.rowCount()
            self._table.insertRow(row)

            name_item = QTableWidgetItem(res.get("name", ""))
            name_item.setData(Qt.UserRole, res)
            self._table.setItem(row, 0, name_item)

            fw_item = QTableWidgetItem(res.get("framework", "?"))
            fw_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 1, fw_item)

            level = res.get("risk_level", "SAFE")
            score = res.get("risk_score", 0)
            level_item = QTableWidgetItem(level)
            level_item.setTextAlignment(Qt.AlignCenter)
            level_item.setForeground(QColor(get_risk_color(level)))
            self._table.setItem(row, 2, level_item)

            score_item = QTableWidgetItem(str(score))
            score_item.setTextAlignment(Qt.AlignCenter)
            score_item.setForeground(QColor(get_risk_color(level)))
            self._table.setItem(row, 3, score_item)

            files_item = QTableWidgetItem(str(res.get("total_files", 0)))
            files_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, files_item)

            det_count = res.get("total_detections", 0)
            det_item = QTableWidgetItem(str(det_count))
            det_item.setTextAlignment(Qt.AlignCenter)
            if det_count > 0:
                det_item.setForeground(QColor("#FF8C00"))
            self._table.setItem(row, 5, det_item)

    def _filter_resources(self, text: str) -> None:
        filtered = [
            r for r in self._resources
            if text.lower() in r.get("name", "").lower()
            or text.lower() in r.get("framework", "").lower()
            or text.lower() in r.get("risk_level", "").lower()
        ]
        self._populate_table(filtered)

    def _on_row_selected(self, row: int) -> None:
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        res = item.data(Qt.UserRole)
        if not res:
            return

        self._detail_title.setText(res.get("name", "?"))
        level = res.get("risk_level", "SAFE")
        color = get_risk_color(level)
        self._detail_info.setText(
            f"<span style='color:{color};font-weight:600'>{level}</span> — "
            f"Score: {res.get('risk_score', 0)}/100<br>"
            f"Framework: {res.get('framework', '?')}<br>"
            f"Files: {res.get('total_files', 0)} | "
            f"Threats: {res.get('total_detections', 0)}<br>"
            f"Last scan: {str(res.get('last_scan', 'Never'))[:16]}<br>"
            f"Path: <small>{res.get('path', '')}</small>"
        )

        # Load detections
        detections = db.get_detections_for_resource(res.get("name", ""))
        self._detail_detections.clear()
        if detections:
            lines = []
            for det in detections[:20]:
                sev = det.get("severity", "?")
                c = get_severity_color(sev)
                line_info = f" L{det['line_number']}" if det.get("line_number") else ""
                lines.append(
                    f"<span style='color:{c};font-weight:600'>[{sev}]</span> "
                    f"{det.get('rule_name','?')} — "
                    f"<span style='color:#888'>{os.path.basename(det.get('file_path',''))}</span>"
                    f"{line_info}"
                )
            self._detail_detections.setHtml("<br>".join(lines))
        else:
            self._detail_detections.setPlainText("No detections recorded.")

        self._scan_btn.setEnabled(bool(res.get("path")))

    def _rescan_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        res = item.data(Qt.UserRole)
        if res:
            self.request_scan_resource.emit(res.get("path", ""))

    def refresh(self) -> None:
        self._refresh()
