"""
gui/deobfuscation_dialog.py
Dialog allowing safe static-only deobfuscation with detailed logs, layers removed, and diffs.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QSplitter, QFileDialog, QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class DeobfuscationDialog(QDialog):
    """Dialogue panel showing transformation passes, logs, and side-by-side deobfuscation comparisons."""

    def __init__(self, file_path: str, classification: str, confidence: float,
                 entropy: float, logs: list, original_content: str,
                 recovered_content: str, parent=None) -> None:
        super().__init__(parent)
        self.file_path = file_path
        self.classification = classification
        self.confidence = confidence
        self.entropy = entropy
        self.logs = logs
        self.original_content = original_content
        self.recovered_content = recovered_content

        self.setWindowTitle("Code Deobfuscation & Analysis")
        self.resize(1000, 650)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header Info Card
        card = QFrame()
        card.setObjectName("cardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)

        title_lbl = QLabel("Deobfuscation & Static Analysis Payloads")
        title_lbl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title_lbl.setStyleSheet("color: #ffffff; background: transparent;")
        card_layout.addWidget(title_lbl)

        meta_lbl = QLabel(
            f"<b>File:</b> {self.file_path} | "
            f"<b>Type:</b> {self.classification} ({self.confidence}% confidence) | "
            f"<b>Entropy:</b> {self.entropy}"
        )
        meta_lbl.setStyleSheet("color: #abb2bf; background: transparent; font-size: 12px;")
        card_layout.addWidget(meta_lbl)

        layout.addWidget(card)

        # Splitter: Left panel logs, Right panel code comparison
        splitter = QSplitter(Qt.Horizontal)

        # Left Panel (Logs)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        log_lbl = QLabel("Transformations Performed")
        log_lbl.setStyleSheet("color: #abb2bf; font-weight: bold;")
        left_layout.addWidget(log_lbl)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Cascadia Code", 9))
        self._log_view.setStyleSheet("background: #1e222b; color: #61afef; border: 1px solid #282c34;")
        self._log_view.setPlainText("\n".join(self.logs))
        left_layout.addWidget(self._log_view)
        
        splitter.addWidget(left_widget)

        # Right Panel (Code comparison split)
        code_split = QSplitter(Qt.Vertical)

        # Original
        orig_w = QWidget()
        orig_l = QVBoxLayout(orig_w)
        orig_l.setContentsMargins(0, 0, 0, 0)
        orig_lbl = QLabel("Original Code")
        orig_lbl.setStyleSheet("color: #f85149; font-weight: bold;")
        self._orig_view = QTextEdit()
        self._orig_view.setReadOnly(True)
        self._orig_view.setFont(QFont("Cascadia Code", 9))
        self._orig_view.setStyleSheet("background: #1e222b; color: #abb2bf; border: 1px solid #282c34;")
        self._orig_view.setPlainText(self.original_content)
        orig_l.addWidget(orig_lbl)
        orig_l.addWidget(self._orig_view)
        code_split.addWidget(orig_w)

        # Recovered
        rec_w = QWidget()
        rec_l = QVBoxLayout(rec_w)
        rec_l.setContentsMargins(0, 0, 0, 0)
        rec_lbl = QLabel("Recovered Payload")
        rec_lbl.setStyleSheet("color: #98c379; font-weight: bold;")
        self._rec_view = QTextEdit()
        self._rec_view.setReadOnly(True)
        self._rec_view.setFont(QFont("Cascadia Code", 9))
        self._rec_view.setStyleSheet("background: #1e222b; color: #98c379; border: 1px solid #282c34;")
        self._rec_view.setPlainText(self.recovered_content)
        rec_l.addWidget(rec_lbl)
        rec_l.addWidget(self._rec_view)
        code_split.addWidget(rec_w)

        splitter.addWidget(code_split)
        splitter.setSizes([300, 700])
        layout.addWidget(splitter, stretch=1)

        # Action Buttons
        btn_layout = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        export_btn = QPushButton("Export Recovered Code...")
        export_btn.clicked.connect(self._export_code)

        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(export_btn)
        layout.addLayout(btn_layout)

    def _export_code(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Code", "", "Source Files (*.lua *.js *.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.recovered_content)
                QMessageBox.information(self, "Success", "Recovered source code exported successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to export code: {e}")
