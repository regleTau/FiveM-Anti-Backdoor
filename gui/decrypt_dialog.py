"""
gui/decrypt_dialog.py
Dialog allowing the user to supply a decryption key for encrypted resource files.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class DecryptDialog(QDialog):
    """Dialogue panel requesting user key/password input for decryption."""

    def __init__(self, file_name: str, parent=None) -> None:
        super().__init__(parent)
        self.file_name = file_name
        self.decryption_key = ""
        
        self.setWindowTitle("Decrypt File")
        self.resize(400, 180)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title/Info
        title = QLabel("Encrypted File Detected")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)

        info = QLabel(f"A valid decryption key is required to scan: {self.file_name}")
        info.setStyleSheet("color: #abb2bf;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Input field
        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("Enter decryption key / password...")
        self._key_input.setEchoMode(QLineEdit.Password)
        self._key_input.setMinimumHeight(34)
        layout.addWidget(self._key_input)

        # Buttons
        btn_layout = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        decrypt_btn = QPushButton("Try Decrypt")
        decrypt_btn.setObjectName("btnPrimary")
        decrypt_btn.setMinimumHeight(34)
        decrypt_btn.clicked.connect(self._on_decrypt_clicked)

        btn_layout.addWidget(cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(decrypt_btn)
        layout.addLayout(btn_layout)

    def _on_decrypt_clicked(self) -> None:
        self.decryption_key = self._key_input.text().strip()
        self.accept()
