"""
gui/decoded_viewer.py
Viewer display showing side-by-side comparison of original obfuscated code vs deobfuscated payload.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QSplitter, QPushButton,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class DecodedViewerWidget(QWidget):
    """View panel showing original and recovered source side by side."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Code Analysis Viewer")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(title)

        splitter = QSplitter(Qt.Horizontal)

        # Original Panel
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_lbl = QLabel("Original Source")
        left_lbl.setStyleSheet("color: #abb2bf; font-weight: bold;")
        self.original_view = QTextEdit()
        self.original_view.setReadOnly(True)
        self.original_view.setFont(QFont("Cascadia Code", 10))
        left_layout.addWidget(left_lbl)
        left_layout.addWidget(self.original_view)
        splitter.addWidget(left)

        # Recovered Panel
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_lbl = QLabel("Recovered / Deobfuscated Source")
        right_lbl.setStyleSheet("color: #98c379; font-weight: bold;")
        self.recovered_view = QTextEdit()
        self.recovered_view.setReadOnly(True)
        self.recovered_view.setFont(QFont("Cascadia Code", 10))
        right_layout.addWidget(right_lbl)
        right_layout.addWidget(self.recovered_view)
        splitter.addWidget(right)

        layout.addWidget(splitter, stretch=1)

    def set_content(self, original: str, recovered: str) -> None:
        self.original_view.setPlainText(original)
        self.recovered_view.setPlainText(recovered)
