"""
gui/reports_widget.py
Reports page — generate and view HTML/JSON scan reports.
"""

import os
import webbrowser
from typing import List, Dict

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QFileDialog, QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from core import database as db
from core.risk_scorer import ResourceScanResult
from reports.html_reporter import generate_html_report
from reports.json_reporter import generate_json_report


def _get_reports_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "scan_reports")
    os.makedirs(path, exist_ok=True)
    return path


class ReportsWidget(QWidget):
    """Reports generation and viewing page."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._last_results: List[ResourceScanResult] = []
        self._build_ui()
        self._load_existing_reports()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("📄  Reports")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()
        layout.addLayout(hdr)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # Generate section
        gen_card = QFrame()
        gen_card.setObjectName("cardFrame")
        gen_layout = QVBoxLayout(gen_card)
        gen_layout.setContentsMargins(20, 16, 20, 16)
        gen_layout.setSpacing(12)

        gen_title = QLabel("Generate Report")
        gen_title.setStyleSheet("color: #6c63ff; font-size: 14px; font-weight: 600; background: transparent;")
        gen_layout.addWidget(gen_title)

        gen_desc = QLabel(
            "Generate reports from the most recent scan. "
            "HTML reports include full detection details and code context. "
            "JSON reports are machine-readable."
        )
        gen_desc.setStyleSheet("color: #9090b0; background: transparent; font-size: 12px;")
        gen_desc.setWordWrap(True)
        gen_layout.addWidget(gen_desc)

        btn_row = QHBoxLayout()
        self._html_btn = QPushButton("Generate HTML Report")
        self._html_btn.setObjectName("btnPrimary")
        self._html_btn.setMinimumHeight(40)
        self._html_btn.clicked.connect(self._gen_html)

        self._json_btn = QPushButton("Generate JSON Report")
        self._json_btn.setMinimumHeight(40)
        self._json_btn.clicked.connect(self._gen_json)

        btn_row.addWidget(self._html_btn)
        btn_row.addWidget(self._json_btn)
        btn_row.addStretch()

        gen_layout.addLayout(btn_row)
        layout.addWidget(gen_card)

        # Existing reports list
        existing_label = QLabel("Existing Reports")
        existing_label.setStyleSheet("color: #6c63ff; font-size: 14px; font-weight: 600; background: transparent;")
        layout.addWidget(existing_label)

        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Filename", "Type", "Size", "Date"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.setColumnWidth(1, 80)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 160)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.doubleClicked.connect(self._open_report)
        layout.addWidget(self._table, stretch=1)

        btn_row2 = QHBoxLayout()
        self._open_btn = QPushButton("Open in Browser")
        self._open_btn.clicked.connect(self._open_selected)

        self._open_folder_btn = QPushButton("Open Reports Folder")
        self._open_folder_btn.clicked.connect(self._open_folder)

        self._delete_btn = QPushButton("Delete Report")
        self._delete_btn.setObjectName("btnDanger")
        self._delete_btn.clicked.connect(self._delete_selected)

        btn_row2.addWidget(self._open_btn)
        btn_row2.addWidget(self._open_folder_btn)
        btn_row2.addStretch()
        btn_row2.addWidget(self._delete_btn)
        layout.addLayout(btn_row2)

    def _load_existing_reports(self) -> None:
        reports_dir = _get_reports_dir()
        self._table.setRowCount(0)
        try:
            files = os.listdir(reports_dir)
        except OSError:
            return

        report_files = [
            f for f in sorted(files, reverse=True)
            if f.endswith((".html", ".json"))
        ]

        for fname in report_files:
            fpath = os.path.join(reports_dir, fname)
            row = self._table.rowCount()
            self._table.insertRow(row)

            name_item = QTableWidgetItem(fname)
            name_item.setData(Qt.UserRole, fpath)
            self._table.setItem(row, 0, name_item)

            ext = os.path.splitext(fname)[1].upper().lstrip(".")
            type_item = QTableWidgetItem(ext)
            type_item.setTextAlignment(Qt.AlignCenter)
            if ext == "HTML":
                type_item.setForeground(QColor("#6c63ff"))
            else:
                type_item.setForeground(QColor("#7bb3ff"))
            self._table.setItem(row, 1, type_item)

            try:
                size = os.path.getsize(fpath)
                size_str = f"{size / 1024:.1f} KB"
            except OSError:
                size_str = "?"
            size_item = QTableWidgetItem(size_str)
            size_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 2, size_item)

            try:
                mtime = os.path.getmtime(fpath)
                from datetime import datetime
                date_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                date_str = "?"
            self._table.setItem(row, 3, QTableWidgetItem(date_str))

    def set_last_results(self, results: List[ResourceScanResult]) -> None:
        """Called after a scan completes to enable report generation."""
        self._last_results = results

    def _gen_html(self) -> None:
        if not self._last_results:
            # Try to generate from DB data
            QMessageBox.information(
                self, "No Scan Results",
                "Please run a scan first, then generate a report."
            )
            return
        try:
            path = generate_html_report(
                self._last_results,
                scan_type="manual",
                target_path="",
            )
            QMessageBox.information(self, "Report Generated", f"HTML report saved to:\n{path}")
            webbrowser.open(f"file:///{path}")
            self._load_existing_reports()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate report:\n{e}")

    def _gen_json(self) -> None:
        if not self._last_results:
            QMessageBox.information(self, "No Scan Results", "Please run a scan first.")
            return
        try:
            path = generate_json_report(self._last_results, scan_type="manual")
            QMessageBox.information(self, "Report Generated", f"JSON report saved to:\n{path}")
            self._load_existing_reports()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate report:\n{e}")

    def _open_report(self) -> None:
        self._open_selected()

    def _open_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        path = item.data(Qt.UserRole)
        if path and os.path.exists(path):
            webbrowser.open(f"file:///{path}")

    def _open_folder(self) -> None:
        folder = _get_reports_dir()
        os.startfile(folder)

    def _delete_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        path = item.data(Qt.UserRole)
        if not path:
            return

        reply = QMessageBox.question(
            self, "Delete Report",
            f"Delete report file?\n{os.path.basename(path)}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                os.remove(path)
                self._load_existing_reports()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def refresh(self) -> None:
        self._load_existing_reports()
