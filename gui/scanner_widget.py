"""
gui/scanner_widget.py
Scanner page — lets user choose scan type, configure path, run scan, and view live progress.
"""

import os
import threading
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QProgressBar, QTextEdit, QFrame, QComboBox, QSizePolicy,
    QSplitter,
)
from PySide6.QtCore import Qt, Signal, QThread, QObject, Slot
from PySide6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor

from core.scanner import (
    run_full_scan, run_quick_scan, run_resource_scan,
    run_folder_scan, ScanProgress, ProgressCallback,
)
from core.risk_scorer import ResourceScanResult
from gui.styles import get_severity_color, get_risk_color


class _ScanWorker(QObject):
    """Worker object that runs the scan in a QThread."""

    progress_signal = Signal(object)   # ScanProgress
    result_signal = Signal(object)     # ResourceScanResult
    finished_signal = Signal(list)     # List[ResourceScanResult]
    error_signal = Signal(str)

    def __init__(self, scan_type: str, path: str, progress: ScanProgress) -> None:
        super().__init__()
        self.scan_type = scan_type
        self.path = path
        self.progress = progress

    @Slot()
    def run(self) -> None:
        try:
            fn_map = {
                "full": run_full_scan,
                "quick": run_quick_scan,
                "resource": run_resource_scan,
                "folder": run_folder_scan,
            }
            fn = fn_map.get(self.scan_type, run_full_scan)

            def _prog_cb(p: ScanProgress) -> None:
                self.progress_signal.emit(p)

            def _res_cb(r: ResourceScanResult) -> None:
                self.result_signal.emit(r)

            results = fn(self.path, progress_cb=_prog_cb,
                         result_cb=_res_cb, progress=self.progress)
            if results is None:
                results = []
            if not isinstance(results, list):
                results = [results]
            self.finished_signal.emit(results)
        except Exception as e:
            self.error_signal.emit(str(e))


class ScannerWidget(QWidget):
    """Scanner page with configuration and live progress."""

    scan_finished = Signal(list)  # List[ResourceScanResult]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[_ScanWorker] = None
        self._progress = ScanProgress()
        self._results: List[ResourceScanResult] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(32, 28, 32, 28)

        # ── Header ────────────────────────────────────────────────────────
        title = QLabel("🔍  FiveM Scanner")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent;")
        layout.addWidget(title)

        subtitle = QLabel("Configure and launch a static analysis scan on your FiveM resources")
        subtitle.setStyleSheet("color: #9090b0; background: transparent;")
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        # ── Config card ───────────────────────────────────────────────────
        config_card = QFrame()
        config_card.setObjectName("cardFrame")
        config_layout = QVBoxLayout(config_card)
        config_layout.setSpacing(14)
        config_layout.setContentsMargins(20, 18, 20, 18)

        # Scan type selector
        type_row = QHBoxLayout()
        type_label = QLabel("Scan Type:")
        type_label.setStyleSheet("color: #9090b0; min-width: 90px; background: transparent;")
        self._type_combo = QComboBox()
        self._type_combo.addItems(["Full Scan", "Quick Scan", "Resource Scan", "Folder Scan"])
        self._type_combo.setMinimumWidth(200)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(type_label)
        type_row.addWidget(self._type_combo)
        type_row.addStretch()

        self._type_desc = QLabel("Recursively scan all files in all resources")
        self._type_desc.setStyleSheet("color: #555570; background: transparent; font-size: 12px;")
        type_row.addWidget(self._type_desc)

        config_layout.addLayout(type_row)

        # Path selector
        path_row = QHBoxLayout()
        path_label = QLabel("Target Path:")
        path_label.setStyleSheet("color: #9090b0; min-width: 90px; background: transparent;")
        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("Select FiveM resources/ directory...")
        self._path_input.setMinimumHeight(36)

        self._browse_btn = QPushButton("Browse")
        self._browse_btn.setMinimumHeight(36)
        self._browse_btn.clicked.connect(self._browse_path)

        path_row.addWidget(path_label)
        path_row.addWidget(self._path_input)
        path_row.addWidget(self._browse_btn)

        config_layout.addLayout(path_row)

        # Action buttons
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("Start Scan")
        self._start_btn.setObjectName("btnPrimary")
        self._start_btn.setMinimumHeight(44)
        self._start_btn.setMinimumWidth(160)
        self._start_btn.clicked.connect(self._start_scan)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("btnDanger")
        self._cancel_btn.setMinimumHeight(44)
        self._cancel_btn.setMinimumWidth(120)
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel_scan)

        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._cancel_btn)
        btn_row.addStretch()

        config_layout.addLayout(btn_row)
        layout.addWidget(config_card)

        # ── Progress ──────────────────────────────────────────────────────
        progress_card = QFrame()
        progress_card.setObjectName("cardFrame")
        prog_layout = QVBoxLayout(progress_card)
        prog_layout.setSpacing(10)
        prog_layout.setContentsMargins(20, 16, 20, 16)

        prog_header = QHBoxLayout()
        prog_title = QLabel("Scan Progress")
        prog_title.setStyleSheet("color: #9090b0; font-size: 12px; font-weight: 600; background: transparent;")
        self._progress_pct = QLabel("0%")
        self._progress_pct.setStyleSheet("color: #6c63ff; font-size: 12px; font-weight: 700; background: transparent;")
        prog_header.addWidget(prog_title)
        prog_header.addStretch()
        prog_header.addWidget(self._progress_pct)
        prog_layout.addLayout(prog_header)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(10)
        prog_layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Ready to scan")
        self._status_label.setStyleSheet("color: #555570; font-size: 11px; background: transparent;")
        prog_layout.addWidget(self._status_label)

        layout.addWidget(progress_card)

        # ── Splitter: log + live results ──────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        # Scan log
        log_frame = QFrame()
        log_frame.setObjectName("cardFrame")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(14, 12, 14, 12)
        log_layout.setSpacing(8)

        log_title = QLabel("Scan Log")
        log_title.setStyleSheet("color: #9090b0; font-size: 11px; font-weight: 600; background: transparent;")
        log_layout.addWidget(log_title)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Cascadia Code", 10))
        self._log_view.setStyleSheet(
            "background: #0a0a14; color: #c8c8e8; border: 1px solid #2d2d4e; border-radius: 6px;"
        )
        log_layout.addWidget(self._log_view)
        splitter.addWidget(log_frame)

        # Live detections
        live_frame = QFrame()
        live_frame.setObjectName("cardFrame")
        live_layout = QVBoxLayout(live_frame)
        live_layout.setContentsMargins(14, 12, 14, 12)
        live_layout.setSpacing(8)

        live_title = QLabel("Live Detections")
        live_title.setStyleSheet("color: #9090b0; font-size: 11px; font-weight: 600; background: transparent;")
        live_layout.addWidget(live_title)

        self._live_view = QTextEdit()
        self._live_view.setReadOnly(True)
        self._live_view.setFont(QFont("Cascadia Code", 10))
        self._live_view.setStyleSheet(
            "background: #0a0a14; color: #c8c8e8; border: 1px solid #2d2d4e; border-radius: 6px;"
        )
        live_layout.addWidget(self._live_view)
        splitter.addWidget(live_frame)

        splitter.setSizes([400, 400])
        layout.addWidget(splitter, stretch=1)

    def _on_type_changed(self, index: int) -> None:
        descs = [
            "Recursively scan all files in all resources",
            "Scan priority files only (manifests, server.lua, client.lua, shared.lua, config.lua)",
            "Select and scan a single FiveM resource directory",
            "Scan a custom folder path",
        ]
        self._type_desc.setText(descs[index])

    def _browse_path(self) -> None:
        scan_type = self._type_combo.currentIndex()
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory", "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
        )
        if directory:
            self._path_input.setText(directory)

    def _start_scan(self) -> None:
        path = self._path_input.text().strip()
        if not path:
            self._log_append("[ERROR] Please select a target path first.", "#FF4444")
            return
        if not os.path.isdir(path):
            self._log_append(f"[ERROR] Directory not found: {path}", "#FF4444")
            return

        scan_type_map = {0: "full", 1: "quick", 2: "resource", 3: "folder"}
        scan_type = scan_type_map[self._type_combo.currentIndex()]

        self._results = []
        self._progress = ScanProgress()
        self._log_view.clear()
        self._live_view.clear()
        self._progress_bar.setValue(0)
        self._progress_pct.setText("0%")

        self._log_append(f"[INFO] Starting {scan_type.upper()} scan...", "#6c63ff")
        self._log_append(f"[INFO] Target: {path}", "#9090b0")
        self._start_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)

        self._thread = QThread()
        self._worker = _ScanWorker(scan_type, path, self._progress)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress_signal.connect(self._on_progress)
        self._worker.result_signal.connect(self._on_result)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.error_signal.connect(self._on_error)
        self._worker.finished_signal.connect(self._thread.quit)
        self._worker.error_signal.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _cancel_scan(self) -> None:
        self._progress.is_cancelled = True
        self._log_append("[INFO] Cancellation requested...", "#FFD700")
        self._cancel_btn.setEnabled(False)

    @Slot(object)
    def _on_progress(self, p: ScanProgress) -> None:
        pct = p.percent
        self._progress_bar.setValue(pct)
        self._progress_pct.setText(f"{pct}%")
        status = (
            f"Resource: {p.current_resource} | "
            f"File: {p.current_file} | "
            f"{p.scanned_resources}/{p.total_resources} resources | "
            f"{p.scanned_files}/{p.total_files} files | "
            f"{p.total_detections} threats"
        )
        self._status_label.setText(status)

        if p.current_resource:
            self._log_append(
                f"[SCAN] {p.current_resource} — {p.current_file}",
                "#555570",
            )

    @Slot(object)
    def _on_result(self, result: ResourceScanResult) -> None:
        self._results.append(result)
        if result.detections:
            color = get_risk_color(result.risk_level)
            self._live_append(
                f"[{result.risk_level}] {result.resource_name} — "
                f"{len(result.detections)} detection(s) — Score: {result.risk_score}/100",
                color,
            )
            for det in result.detections[:3]:  # Show top 3
                sev_color = get_severity_color(det.severity)
                self._live_append(
                    f"  [{det.severity}] {det.rule_name} — {os.path.basename(det.file_path)}"
                    f"{f' L{det.line_number}' if det.line_number else ''}",
                    sev_color,
                )
        else:
            self._live_append(
                f"[SAFE] {result.resource_name} — clean",
                "#4CAF50",
            )

    @Slot(list)
    def _on_finished(self, results: list) -> None:
        self._results = results
        total_threats = sum(len(r.detections) for r in results)
        self._log_append(
            f"\n[DONE] Scan complete. {len(results)} resources, {total_threats} threats detected.",
            "#6c63ff",
        )
        self._start_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress_bar.setValue(100)
        self._progress_pct.setText("100%")
        self._status_label.setText(
            f"Scan complete — {len(results)} resources, {total_threats} threats"
        )
        self.scan_finished.emit(results)

    @Slot(str)
    def _on_error(self, error: str) -> None:
        self._log_append(f"[ERROR] {error}", "#FF4444")
        self._start_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)

    def _log_append(self, text: str, color: str = "#c8c8e8") -> None:
        cursor = self._log_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        self._log_view.setTextCursor(cursor)
        self._log_view.ensureCursorVisible()

    def _live_append(self, text: str, color: str = "#c8c8e8") -> None:
        cursor = self._live_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        self._live_view.setTextCursor(cursor)
        self._live_view.ensureCursorVisible()

    def set_path(self, path: str) -> None:
        self._path_input.setText(path)

    def trigger_quick_scan(self, path: str) -> None:
        self._path_input.setText(path)
        self._type_combo.setCurrentIndex(1)
        self._start_scan()

    def trigger_full_scan(self, path: str) -> None:
        self._path_input.setText(path)
        self._type_combo.setCurrentIndex(0)
        self._start_scan()
