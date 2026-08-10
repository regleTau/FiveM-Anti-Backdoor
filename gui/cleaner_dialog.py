"""
gui/cleaner_dialog.py
Safe code remover dialog with file diff, preview, backups, and quarantine fallback.
"""

import os
from PySide6.QtWidgets import (
    QWidget, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QMessageBox, QSplitter,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from core.backup_manager import backup_file
from core.quarantine_manager import quarantine_file


class CleanerDialog(QDialog):
    """Safe Code Remover dialog box showing before/after diff of code modifications."""

    def __init__(self, file_path: str, resource_name: str, detection_name: str,
                 parent=None) -> None:
        super().__init__(parent)
        self.file_path = file_path
        self.resource_name = resource_name
        self.detection_name = detection_name
        self.cleaned_content = ""
        self.original_content = ""
        self.unsafe_to_clean = False

        self.setWindowTitle("🛡️ Safe Code Remover")
        self.resize(1000, 650)
        self._build_ui()
        self._load_and_prepare_diff()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header Info
        header_lbl = QLabel("Safe Code Remover")
        header_lbl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        header_lbl.setStyleSheet("color: #ffffff;")
        layout.addWidget(header_lbl)

        info_lbl = QLabel(
            "Review the proposed changes below. Only the specific detected code lines will be commented/removed. "
            "A backup copy will be saved before modification."
        )
        info_lbl.setStyleSheet("color: #abb2bf;")
        layout.addWidget(info_lbl)

        # File and Path info card
        card = QFrame()
        card.setObjectName("cardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 10, 14, 10)

        self._path_lbl = QLabel(f"<b>File:</b> {self.file_path}")
        self._path_lbl.setStyleSheet("color: #abb2bf; background: transparent;")
        card_layout.addWidget(self._path_lbl)

        self._reason_lbl = QLabel(f"<b>Detection:</b> {self.detection_name}")
        self._reason_lbl.setStyleSheet("color: #d19a66; background: transparent;")
        card_layout.addWidget(self._reason_lbl)

        layout.addWidget(card)

        # Splitter for diff view
        splitter = QSplitter(Qt.Horizontal)

        # Left panel: Original (Before)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_lbl = QLabel("Before (Original)")
        left_lbl.setStyleSheet("color: #f85149; font-weight: bold;")
        self._original_view = QTextEdit()
        self._original_view.setReadOnly(True)
        self._original_view.setFont(QFont("Cascadia Code", 10))
        self._original_view.setStyleSheet("background: #1e222b; border: 1px solid #282c34; color: #abb2bf;")
        left_layout.addWidget(left_lbl)
        left_layout.addWidget(self._original_view)
        splitter.addWidget(left_widget)

        # Right panel: Cleaned (After)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_lbl = QLabel("After (Cleaned)")
        right_lbl.setStyleSheet("color: #98c379; font-weight: bold;")
        self._cleaned_view = QTextEdit()
        self._cleaned_view.setReadOnly(True)
        self._cleaned_view.setFont(QFont("Cascadia Code", 10))
        self._cleaned_view.setStyleSheet("background: #1e222b; border: 1px solid #282c34; color: #abb2bf;")
        right_layout.addWidget(right_lbl)
        right_layout.addWidget(self._cleaned_view)
        splitter.addWidget(right_widget)

        layout.addWidget(splitter, stretch=1)

        # Bottom warning area (if unsafe to clean)
        self._warning_lbl = QLabel("")
        self._warning_lbl.setStyleSheet("color: #f85149; font-weight: bold; background: transparent;")
        self._warning_lbl.setVisible(False)
        layout.addWidget(self._warning_lbl)

        # Bottom buttons
        btn_layout = QHBoxLayout()
        self._btn_cancel = QPushButton("Cancel")
        self._btn_cancel.clicked.connect(self.reject)

        self._btn_clean = QPushButton("Apply Safe Clean")
        self._btn_clean.setObjectName("btnPrimary")
        self._btn_clean.setMinimumHeight(38)
        self._btn_clean.clicked.connect(self._apply_clean)

        self._btn_quarantine = QPushButton("Quarantine File")
        self._btn_quarantine.setObjectName("btnDanger")
        self._btn_quarantine.setVisible(False)
        self._btn_quarantine.clicked.connect(self._quarantine_instead)

        btn_layout.addWidget(self._btn_cancel)
        btn_layout.addStretch()
        btn_layout.addWidget(self._btn_quarantine)
        btn_layout.addWidget(self._btn_clean)

        layout.addLayout(btn_layout)

    def _load_and_prepare_diff(self) -> None:
        if not os.path.isfile(self.file_path):
            QMessageBox.warning(self, "Error", "Target file does not exist.")
            self.reject()
            return

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                self.original_content = f.read()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read file: {e}")
            self.reject()
            return

        self._original_view.setPlainText(self.original_content)

        lines = self.original_content.splitlines()
        cleaned_lines = []
        modified = False

        # Identify targets for safe clean
        bad_keywords = ["loadstring", "os.execute", "io.popen", "eval(", "Function("]
        
        # Check if the entire file seems highly obfuscated or packed.
        # If so, automatic removal of specific lines is unsafe.
        long_lines = [l for l in lines if len(l) > 1000]
        if len(long_lines) > 2 or self.original_content.count("string.char") > 15:
            self.unsafe_to_clean = True

        for i, line in enumerate(lines):
            # Check if line contains bad keywords and is not commented
            has_bad = any(kw in line for kw in bad_keywords)
            is_comment = line.strip().startswith(("--", "//", "/*", "*"))
            
            if has_bad and not is_comment and not self.unsafe_to_clean:
                # Comment out safely
                if self.file_path.endswith((".js", ".html")):
                    cleaned_lines.append(f"// [SAFE CLEAN] Commented out bad code:\n// {line}")
                else:
                    cleaned_lines.append(f"-- [SAFE CLEAN] Commented out bad code:\n-- {line}")
                modified = True
            else:
                cleaned_lines.append(line)

        self.cleaned_content = "\n".join(cleaned_lines)
        self._cleaned_view.setPlainText(self.cleaned_content)

        if self.unsafe_to_clean or not modified:
            self.unsafe_to_clean = True
            self._warning_lbl.setText("⚠️ Unsafe to automatically remove. Entire file structure is obfuscated or complex.")
            self._warning_lbl.setVisible(True)
            self._btn_clean.setEnabled(False)
            self._btn_quarantine.setVisible(True)

    def _apply_clean(self) -> None:
        print(f"[DEBUG] _apply_clean triggered. unsafe_to_clean={self.unsafe_to_clean}")
        if self.unsafe_to_clean:
            return

        reply = QMessageBox.question(
            self, "Confirm Modification",
            "Do you want to apply the safe clean code changes? A backup will be generated automatically.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        print(f"[DEBUG] User confirmation reply: {reply}")
        if reply == QMessageBox.Yes or str(reply).endswith("Yes") or int(reply) == int(QMessageBox.Yes):
            # Create backup
            backup_path = backup_file(self.file_path, self.resource_name, reason="Safe Cleaner")
            print(f"[DEBUG] Backup created at: {backup_path}")
            if not backup_path:
                QMessageBox.warning(self, "Backup Failed", "Could not create backup file. Safe Clean aborted.")
                return

            try:
                with open(self.file_path, "w", encoding="utf-8") as f:
                    f.write(self.cleaned_content)
                QMessageBox.information(self, "Clean Complete", f"File safely updated. Backup saved to backups/.")
                self.accept()
            except Exception as e:
                print(f"[DEBUG] Write error: {e}")
                QMessageBox.warning(self, "Error", f"Failed to write changes: {e}")

    def _quarantine_instead(self) -> None:
        reply = QMessageBox.question(
            self, "Confirm Quarantine",
            "Quarantine this file? It will be safely moved out of the resource directory.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            res = quarantine_file(
                file_path=self.file_path,
                resource_name=self.resource_name,
                detection_reason="Unsafe to clean manually",
                rule_id="MANUAL-CLEAN-FALLBACK",
                risk_score=99,
                risk_level="CRITICAL",
            )
            if res:
                QMessageBox.information(self, "Quarantined", "File moved to quarantine successfully.")
                self.accept()
            else:
                QMessageBox.warning(self, "Error", "Failed to quarantine file.")
