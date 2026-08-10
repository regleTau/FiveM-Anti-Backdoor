"""
gui/quarantine_widget.py
Quarantine management page — view, restore, and permanently delete quarantined files.
"""

import os
from typing import List, Dict, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QSplitter, QTextEdit, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from core import database as db
from core.quarantine_manager import (
    restore_quarantined_file, delete_quarantine_item, get_quarantine_details,
)
from gui.styles import get_risk_color, get_severity_color


class QuarantineWidget(QWidget):
    """Quarantine management page."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._items: List[Dict] = []
        self._build_ui()
        self._refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("🔒  Quarantine")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh)
        hdr.addWidget(refresh_btn)

        layout.addLayout(hdr)

        subtitle = QLabel(
            "Files quarantined here are isolated and cannot be loaded by your FiveM server. "
            "You can restore or permanently delete them."
        )
        subtitle.setStyleSheet("color: #9090b0; background: transparent; font-size: 12px;")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # Count label
        self._count_label = QLabel("No quarantined files")
        self._count_label.setStyleSheet("color: #9090b0; background: transparent; font-size: 12px;")
        layout.addWidget(self._count_label)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels([
            "Resource", "Filename", "Risk Level", "Reason", "Score", "Quarantined"
        ])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.setColumnWidth(2, 100)
        self._table.setColumnWidth(4, 70)
        self._table.setColumnWidth(5, 150)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.currentCellChanged.connect(lambda r, c, pr, pc: self._on_row_selected(r))
        splitter.addWidget(self._table)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setObjectName("cardFrame")
        detail_frame.setMinimumWidth(340)
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(10)

        self._detail_title = QLabel("Select an item")
        self._detail_title.setFont(QFont("Segoe UI", 13, QFont.Bold))
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

        preview_label = QLabel("File Content Preview")
        preview_label.setStyleSheet("color: #6c63ff; font-size: 11px; font-weight: 600; background: transparent;")
        detail_layout.addWidget(preview_label)

        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFont(QFont("Cascadia Code", 10))
        self._preview.setStyleSheet(
            "background: #0a0a14; border: 1px solid #2d2d4e; border-radius: 6px; color: #c8c8e8;"
        )
        detail_layout.addWidget(self._preview, stretch=1)

        # Action buttons
        btn_layout = QHBoxLayout()
        self._restore_btn = QPushButton("Restore")
        self._restore_btn.setObjectName("btnSuccess")
        self._restore_btn.setEnabled(False)
        self._restore_btn.clicked.connect(self._restore_selected)

        self._delete_btn = QPushButton("Delete Permanently")
        self._delete_btn.setObjectName("btnDanger")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._delete_selected)

        btn_layout.addWidget(self._restore_btn)
        btn_layout.addWidget(self._delete_btn)
        detail_layout.addLayout(btn_layout)

        splitter.addWidget(detail_frame)
        splitter.setSizes([580, 380])
        layout.addWidget(splitter, stretch=1)

    def _refresh(self) -> None:
        self._items = db.get_quarantine_items()
        count = len(self._items)
        self._count_label.setText(
            f"{count} quarantined file{'s' if count != 1 else ''}"
        )
        self._populate_table(self._items)

    def _populate_table(self, items: List[Dict]) -> None:
        self._table.setRowCount(0)
        for item in items:
            row = self._table.rowCount()
            self._table.insertRow(row)

            res_item = QTableWidgetItem(item.get("resource_name", ""))
            res_item.setData(Qt.UserRole, item)
            self._table.setItem(row, 0, res_item)

            self._table.setItem(row, 1, QTableWidgetItem(item.get("filename", "")))

            level = item.get("risk_level", "UNKNOWN")
            level_item = QTableWidgetItem(level)
            level_item.setTextAlignment(Qt.AlignCenter)
            level_item.setForeground(QColor(get_risk_color(level)))
            self._table.setItem(row, 2, level_item)

            reason = item.get("detection_reason", "")[:80]
            self._table.setItem(row, 3, QTableWidgetItem(reason))

            score_item = QTableWidgetItem(str(item.get("risk_score", 0)))
            score_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, score_item)

            q_date = str(item.get("quarantined_at", ""))[:16]
            self._table.setItem(row, 5, QTableWidgetItem(q_date))

    def _on_row_selected(self, row: int) -> None:
        if row < 0:
            return
        item_data = self._table.item(row, 0)
        if not item_data:
            return
        q_item = item_data.data(Qt.UserRole)
        if not q_item:
            return

        qid = q_item.get("id")
        details = get_quarantine_details(qid) if qid else q_item

        self._detail_title.setText(q_item.get("filename", "?"))
        level = q_item.get("risk_level", "?")
        color = get_risk_color(level)
        self._detail_info.setText(
            f"Risk: <span style='color:{color};font-weight:600'>{level}</span> "
            f"(Score: {q_item.get('risk_score', 0)}/100)<br>"
            f"Resource: {q_item.get('resource_name', '?')}<br>"
            f"Original: {q_item.get('original_path', '?')}<br>"
            f"SHA-256: {str(q_item.get('sha256', ''))[:32]}...<br>"
            f"Rule: {q_item.get('rule_id', '?')}<br>"
            f"Reason: {q_item.get('detection_reason', '?')[:100]}<br>"
            f"Quarantined: {str(q_item.get('quarantined_at', ''))[:16]}"
        )

        if details and details.get("content_preview"):
            self._preview.setPlainText(details["content_preview"])
        else:
            self._preview.setPlainText("[No preview available]")

        self._restore_btn.setEnabled(True)
        self._delete_btn.setEnabled(True)

    def _restore_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item_data = self._table.item(row, 0)
        if not item_data:
            return
        q_item = item_data.data(Qt.UserRole)
        if not q_item:
            return

        reply = QMessageBox.question(
            self,
            "Restore File",
            f"Restore '{q_item.get('filename')}' to:\n{q_item.get('original_path')}?\n\n"
            "⚠️ Warning: This restores a potentially malicious file.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            qid = q_item.get("id")
            if qid and restore_quarantined_file(qid):
                QMessageBox.information(self, "Restored", "File restored successfully.")
            else:
                QMessageBox.warning(self, "Error", "Failed to restore file.")
            self._refresh()

    def _delete_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item_data = self._table.item(row, 0)
        if not item_data:
            return
        q_item = item_data.data(Qt.UserRole)
        if not q_item:
            return

        reply = QMessageBox.question(
            self,
            "Delete Permanently",
            f"Permanently delete '{q_item.get('filename')}'?\n\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            qid = q_item.get("id")
            if qid and delete_quarantine_item(qid):
                QMessageBox.information(self, "Deleted", "File permanently deleted.")
            else:
                QMessageBox.warning(self, "Error", "Failed to delete file.")
            self._refresh()

    def quarantine_detection(self, detection: Dict) -> None:
        """Called from threats widget to quarantine a file."""
        from core.quarantine_manager import quarantine_file

        file_path = detection.get("file_path", "")
        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(
                self, "Cannot Quarantine",
                f"File not found:\n{file_path}\n\nThe file may have already been moved or deleted."
            )
            return

        reply = QMessageBox.question(
            self,
            "Quarantine File",
            f"Quarantine file?\n\n{file_path}\n\n"
            "The file will be moved to the quarantine directory and can be restored later.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            result = quarantine_file(
                file_path=file_path,
                resource_name=detection.get("resource_name", "unknown"),
                detection_reason=detection.get("description", ""),
                rule_id=detection.get("rule_id", ""),
                risk_score=0,
                risk_level="UNKNOWN",
            )
            if result:
                QMessageBox.information(
                    self, "Quarantined",
                    f"File quarantined successfully.\nBacked up to: {result.get('quarantine_path', '')}"
                )
                self._refresh()
            else:
                QMessageBox.warning(self, "Error", "Failed to quarantine file.")

    def refresh(self) -> None:
        self._refresh()
