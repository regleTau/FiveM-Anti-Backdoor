"""
gui/rules_widget.py
Rules page — view and toggle security rules/signatures.
"""

from typing import List, Dict

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QLineEdit, QComboBox, QCheckBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from core import database as db
from gui.styles import get_severity_color


class RulesWidget(QWidget):
    """Security rules management page."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rules: List[Dict] = []
        self._build_ui()
        self._refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("🛡️  Security Rules")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔎 Search rules...")
        self._search.setMaximumWidth(280)
        self._search.setMinimumHeight(34)
        self._search.textChanged.connect(self._apply_filters)
        hdr.addWidget(self._search)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh)
        hdr.addWidget(refresh_btn)

        layout.addLayout(hdr)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "Rule ID", "Name", "Severity", "Confidence", "Type", "Status"
        ])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.setColumnWidth(0, 160)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(3, 100)
        self._table.setColumnWidth(4, 100)
        self._table.setColumnWidth(5, 80)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table, stretch=1)

    def _refresh(self) -> None:
        db.init_database()
        # Load rules from DB
        self._rules = db.get_all_rules()
        self._apply_filters()

    def _apply_filters(self) -> None:
        search_text = self._search.text().lower()
        filtered = self._rules
        if search_text:
            filtered = [
                r for r in filtered
                if search_text in r.get("rule_id", "").lower()
                or search_text in r.get("name", "").lower()
                or search_text in r.get("description", "").lower()
            ]
        self._populate_table(filtered)

    def _populate_table(self, rules: List[Dict]) -> None:
        self._table.setRowCount(0)
        for r in rules:
            row = self._table.rowCount()
            self._table.insertRow(row)

            rule_id = r.get("rule_id", "")
            id_item = QTableWidgetItem(rule_id)
            self._table.setItem(row, 0, id_item)

            name_item = QTableWidgetItem(r.get("name", ""))
            self._table.setItem(row, 1, name_item)

            sev = r.get("severity", "LOW")
            sev_item = QTableWidgetItem(sev)
            sev_item.setTextAlignment(Qt.AlignCenter)
            sev_item.setForeground(QColor(get_severity_color(sev)))
            sev_item.setFont(QFont("Segoe UI", 11, QFont.Bold))
            self._table.setItem(row, 2, sev_item)

            conf_item = QTableWidgetItem(f"{r.get('confidence', 0)}%")
            conf_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 3, conf_item)

            type_item = QTableWidgetItem(r.get("pattern_type", "regex"))
            type_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, type_item)

            # Checkbox for status
            checkbox = QCheckBox()
            checkbox.setChecked(bool(r.get("enabled", 1)))
            checkbox.setStyleSheet("margin-left: 20%; background: transparent;")
            # Connect toggle handler
            checkbox.stateChanged.connect(
                lambda state, rid=rule_id: self._toggle_rule(rid, state == Qt.Checked)
            )

            self._table.setCellWidget(row, 5, checkbox)

    def _toggle_rule(self, rule_id: str, checked: bool) -> None:
        db.toggle_rule(rule_id, checked)

    def refresh(self) -> None:
        self._refresh()
