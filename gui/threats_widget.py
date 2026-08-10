"""
gui/threats_widget.py
Threats page — shows all detections with details, code context, and clean/quarantine/restore/safe actions.
"""

import os
from typing import List, Dict, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QLineEdit, QSplitter, QTextEdit, QComboBox, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from core import database as db
from core.backup_manager import list_backups, restore_file
from core.quarantine_manager import quarantine_file
from gui.styles import get_severity_color, get_risk_color
from gui.cleaner_dialog import CleanerDialog


class ThreatsWidget(QWidget):
    """Threats / Detections page."""

    request_quarantine = Signal(dict)   # detection dict

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._detections: List[Dict] = []
        self._build_ui()
        self._refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 28, 32, 28)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("⚠️  Threats")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        hdr.addWidget(title)
        hdr.addStretch()

        # Filter by severity
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._sev_filter.setMinimumWidth(120)
        self._sev_filter.currentIndexChanged.connect(self._apply_filters)
        hdr.addWidget(QLabel("Severity:"))
        hdr.addWidget(self._sev_filter)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔎 Search threats...")
        self._search.setMaximumWidth(240)
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

        # Summary bar
        self._summary_bar = QLabel("")
        self._summary_bar.setStyleSheet("color: #abb2bf; background: transparent; font-size: 12px;")
        layout.addWidget(self._summary_bar)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)

        # Detections table
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "Severity", "Resource", "File", "Line", "Detection", "Confidence", "Risk", "Rule ID"
        ])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._table.setColumnWidth(0, 90)
        self._table.setColumnWidth(2, 130)
        self._table.setColumnWidth(3, 60)
        self._table.setColumnWidth(5, 90)
        self._table.setColumnWidth(6, 70)
        self._table.setColumnWidth(7, 140)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.currentCellChanged.connect(lambda r, c, pr, pc: self._on_row_selected(r))
        splitter.addWidget(self._table)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setObjectName("cardFrame")
        detail_frame.setMinimumWidth(380)
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(8)

        self._det_title = QLabel("Select a detection")
        self._det_title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self._det_title.setStyleSheet("color: #ffffff; background: transparent;")
        self._det_title.setWordWrap(True)
        detail_layout.addWidget(self._det_title)

        self._det_badges = QLabel("")
        self._det_badges.setStyleSheet("background: transparent;")
        detail_layout.addWidget(self._det_badges)

        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.HLine)
        detail_layout.addWidget(sep2)

        self._det_meta = QLabel("")
        self._det_meta.setStyleSheet("color: #abb2bf; background: transparent; font-size: 12px;")
        self._det_meta.setWordWrap(True)
        detail_layout.addWidget(self._det_meta)

        self._det_desc = QLabel("")
        self._det_desc.setStyleSheet("color: #abb2bf; background: transparent; font-size: 12px;")
        self._det_desc.setWordWrap(True)
        detail_layout.addWidget(self._det_desc)

        self._det_rec = QLabel("")
        self._det_rec.setStyleSheet("color: #56b6c2; background: transparent; font-size: 12px;")
        self._det_rec.setWordWrap(True)
        detail_layout.addWidget(self._det_rec)

        ctx_label = QLabel("Code Context")
        ctx_label.setStyleSheet("color: #abb2bf; font-size: 11px; font-weight: 600; background: transparent;")
        detail_layout.addWidget(ctx_label)

        self._det_code = QTextEdit()
        self._det_code.setReadOnly(True)
        self._det_code.setFont(QFont("Cascadia Code", 10))
        self._det_code.setStyleSheet(
            "background: #1e222b; border: 1px solid #282c34; border-radius: 4px; color: #abb2bf;"
        )
        self._det_code.setMaximumHeight(140)
        detail_layout.addWidget(self._det_code)

        # Actions buttons layout
        btn_layout_1 = QHBoxLayout()
        self._clean_btn = QPushButton("Clean Bad Code")
        self._clean_btn.setObjectName("btnPrimary")
        self._clean_btn.setEnabled(False)
        self._clean_btn.clicked.connect(self._clean_selected)

        self._quarantine_btn = QPushButton("Quarantine")
        self._quarantine_btn.setObjectName("btnWarning")
        self._quarantine_btn.setEnabled(False)
        self._quarantine_btn.clicked.connect(self._quarantine_selected)

        btn_layout_1.addWidget(self._clean_btn)
        btn_layout_1.addWidget(self._quarantine_btn)
        detail_layout.addLayout(btn_layout_1)

        btn_layout_2 = QHBoxLayout()
        self._restore_btn = QPushButton("Restore Original")
        self._restore_btn.setEnabled(False)
        self._restore_btn.clicked.connect(self._restore_selected)

        self._safe_btn = QPushButton("Mark As Safe")
        self._safe_btn.setEnabled(False)
        self._safe_btn.clicked.connect(self._mark_safe_selected)

        btn_layout_2.addWidget(self._restore_btn)
        btn_layout_2.addWidget(self._safe_btn)
        detail_layout.addLayout(btn_layout_2)

        btn_layout_3 = QHBoxLayout()
        self._analyze_btn = QPushButton("Analyze / Deobfuscate")
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.clicked.connect(self._analyze_selected)
        btn_layout_3.addWidget(self._analyze_btn)
        detail_layout.addLayout(btn_layout_3)

        detail_layout.addStretch()
        splitter.addWidget(detail_frame)
        splitter.setSizes([620, 420])
        layout.addWidget(splitter, stretch=1)

    def _refresh(self) -> None:
        self._detections = db.get_all_detections(500)
        summary = db.get_detection_summary()
        self._summary_bar.setText(
            f"Total: {summary['total']}  |  "
            f"Critical: {summary['critical']}  |  "
            f"High: {summary['high']}  |  "
            f"Medium: {summary['medium']}  |  "
            f"Low: {summary['low']}"
        )
        self._apply_filters()

    def _apply_filters(self) -> None:
        sev_filter = self._sev_filter.currentText()
        search_text = self._search.text().lower()

        filtered = self._detections
        if sev_filter != "All":
            filtered = [d for d in filtered if d.get("severity") == sev_filter]
        if search_text:
            filtered = [
                d for d in filtered
                if search_text in d.get("resource_name", "").lower()
                or search_text in d.get("rule_name", "").lower()
                or search_text in d.get("file_path", "").lower()
                or search_text in d.get("rule_id", "").lower()
            ]
        self._populate_table(filtered)

    def _populate_table(self, detections: List[Dict]) -> None:
        self._table.setRowCount(0)
        for det in detections:
            row = self._table.rowCount()
            self._table.insertRow(row)

            sev = det.get("severity", "?")
            sev_item = QTableWidgetItem(sev)
            sev_item.setTextAlignment(Qt.AlignCenter)
            sev_item.setForeground(QColor(get_severity_color(sev)))
            sev_item.setFont(QFont("Segoe UI", 11, QFont.Bold))
            sev_item.setData(Qt.UserRole, det)
            self._table.setItem(row, 0, sev_item)

            self._table.setItem(row, 1, QTableWidgetItem(det.get("resource_name", "")))

            fname = os.path.basename(det.get("file_path", ""))
            self._table.setItem(row, 2, QTableWidgetItem(fname))

            line = det.get("line_number")
            line_item = QTableWidgetItem(str(line) if line else "")
            line_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 3, line_item)

            self._table.setItem(row, 4, QTableWidgetItem(det.get("rule_name", "")))

            conf = det.get("confidence", 0)
            conf_item = QTableWidgetItem(f"{conf}%")
            conf_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 5, conf_item)

            # Risk Score
            sev_weight = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "LOW": 3}.get(sev.upper(), 3)
            risk_score = min(100, int(sev_weight * (conf / 100.0) * 3))
            risk_item = QTableWidgetItem(f"{risk_score}")
            risk_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 6, risk_item)

            self._table.setItem(row, 7, QTableWidgetItem(det.get("rule_id", "")))

    def _on_row_selected(self, row: int) -> None:
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if not det:
            return

        sev = det.get("severity", "?")
        sev_color = get_severity_color(sev)
        conf = det.get("confidence", 0)

        # Risk Calculation
        sev_weight = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "LOW": 3}.get(sev.upper(), 3)
        risk_score = min(100, int(sev_weight * (conf / 100.0) * 3))

        # Category detection
        rule_id = det.get("rule_id", "")
        if "BACK" in rule_id:
            category = "Backdoor / C2 Loader"
        elif "OBF" in rule_id:
            category = "Obfuscated payload"
        elif "JS" in rule_id:
            category = "NUI JavaScript Vulnerability"
        elif "MANIFEST" in rule_id:
            category = "FXManifest Error"
        else:
            category = "Suspicious Event/API"

        fp_risk = "HIGH" if (conf < 60 or sev in ["LOW", "MEDIUM"]) else "LOW"

        self._det_title.setText(det.get("rule_name", "Unknown Rule"))
        self._det_badges.setText(
            f"<span style='background:{sev_color};color:#181a1f;padding:2px 8px;"
            f"border-radius:3px;font-size:11px;font-weight:600'>{sev}</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:#abb2bf;font-size:12px'>Confidence: {conf}%</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:#abb2bf;font-size:12px'>Risk Score: {risk_score}/100</span>"
        )
        self._det_meta.setText(
            f"<b>Resource:</b> {det.get('resource_name', '?')}<br>"
            f"<b>File:</b> {os.path.basename(det.get('file_path', ''))}<br>"
            f"<b>Path:</b> <small>{det.get('file_path', '?')}</small><br>"
            f"<b>Line:</b> {det.get('line_number', 'N/A')}<br>"
            f"<b>Rule ID:</b> {rule_id}<br>"
            f"<b>Category:</b> {category}<br>"
            f"<b>False-Positive Risk:</b> <span style='font-weight:bold'>{fp_risk}</span>"
        )
        self._det_desc.setText(f"<b>Explanation:</b> {det.get('description', '')}")
        self._det_rec.setText(f"<b>Recommendation:</b> {det.get('recommendation', '')}")
        self._det_code.setPlainText(det.get("code_context", ""))
        
        self._clean_btn.setEnabled(bool(det.get("file_path")))
        self._quarantine_btn.setEnabled(bool(det.get("file_path")))
        self._restore_btn.setEnabled(bool(det.get("file_path")))
        self._safe_btn.setEnabled(bool(det.get("file_path")))
        self._analyze_btn.setEnabled(bool(det.get("file_path")))

    def _clean_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if not det:
            return

        file_path = det.get("file_path", "")
        # Call Safe Cleaner Dialog
        dialog = CleanerDialog(file_path, det.get("resource_name", "unknown"), det.get("rule_name", "Threat"), parent=self)
        if dialog.exec():
            # Delete this detection from DB since it has been cleaned
            db.delete_detection(det.get("id"))
            self._refresh()

    def _quarantine_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if det:
            self.request_quarantine.emit(det)

    def _restore_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if not det:
            return

        file_path = det.get("file_path", "")
        resource_name = det.get("resource_name", "")

        backups = list_backups(resource_name)
        # Find the most recent backup matching the original path
        matching_backups = [b for b in backups if b.get("original_path") == file_path]
        if not matching_backups:
            QMessageBox.warning(self, "No Backups", f"No backups found for file: {os.path.basename(file_path)}")
            return

        most_recent = matching_backups[0]
        backup_path = most_recent.get("backup_path", "")

        reply = QMessageBox.question(
            self, "Restore Original",
            f"Restore original file from backup?\n\nBackup date: {most_recent.get('backed_up_at', '')}\nReason: {most_recent.get('reason', '')}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if restore_file(backup_path, file_path):
                QMessageBox.information(self, "Restored", "Original file restored successfully. Run a re-scan to update scores.")
                self._refresh()
            else:
                QMessageBox.warning(self, "Error", "Failed to restore file.")

    def _mark_safe_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if not det:
            return

        # Extract target line
        line_content = ""
        if det.get("code_context"):
            for line in det.get("code_context").splitlines():
                if ">>>" in line:
                    line_content = line.replace(">>>", "").strip()
                    break
        if not line_content:
            line_content = det.get("matched_pattern", "")

        reply = QMessageBox.question(
            self, "Mark As Safe",
            f"Mark this signature as safe?\n\nFile: {os.path.basename(det.get('file_path',''))}\nRule: {det.get('rule_name','')}\nLine: {line_content[:100]}\n\nThis exact pattern will be ignored in future scans.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            db.mark_detection_safe(det.get("file_path"), line_content, det.get("rule_id"))
            db.delete_detection(det.get("id"))
            self._refresh()

    def refresh(self) -> None:
        self._refresh()

    def _analyze_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        det = item.data(Qt.UserRole)
        if not det:
            return
        file_path = det.get("file_path", "")
        if not file_path or not os.path.exists(file_path):
            return

        from core.transformation_pipeline import TransformationPipeline
        from gui.deobfuscation_dialog import DeobfuscationDialog
        from gui.decrypt_dialog import DecryptDialog

        pipeline = TransformationPipeline()
        res = pipeline.process_file(file_path)

        if res.get("decryption_status") == "Requires key":
            diag = DecryptDialog(os.path.basename(file_path), parent=self)
            if diag.exec():
                res = pipeline.process_file(file_path, diag.decryption_key)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                orig_content = f.read()
        except Exception:
            orig_content = ""

        dialog = DeobfuscationDialog(
            file_path=file_path,
            classification=res.get("classification", "TEXT"),
            confidence=res.get("confidence", 100.0),
            entropy=res.get("entropy", 0.0),
            logs=res.get("logs", []),
            original_content=orig_content,
            recovered_content=res.get("recovered_content", orig_content),
            parent=self
        )
        dialog.exec()
