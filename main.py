"""
main.py
Application entry point for FiveM Anti-Backdoor & Bad Code Remover.
Initializes SQLite database schema, imports default rules, and launches GUI.
"""

import sys
import os
import json

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow
from core import database as db


def init_app() -> None:
    """Initialize application environment and database."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create required folder structures
    for folder in ["quarantine", "backups", "scan_reports"]:
        os.makedirs(os.path.join(base_dir, folder), exist_ok=True)

    # Initialize SQLite database
    db.init_database()
    db.clear_active_scan_data()

    # Load default signature rules into rules table
    sig_dir = os.path.join(base_dir, "signatures")
    if os.path.exists(sig_dir):
        sig_files = [
            "fivem_backdoors.json",
            "fivem_suspicious.json",
            "lua_obfuscation.json",
            "javascript_suspicious.json",
            "fxmanifest_rules.json",
        ]
        for f in sig_files:
            fpath = os.path.join(sig_dir, f)
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as file:
                        rules_data = json.load(file)
                    for rule in rules_data.get("rules", []):
                        rule["source_file"] = f
                        db.upsert_rule(rule)
                except Exception as e:
                    print(f"Failed to import rule file {f}: {e}")


def main() -> None:
    # Set high DPI scaling properties for modern display rendering
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    # Initialize DB & Directories
    init_app()

    # Start PySide6 Application
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
