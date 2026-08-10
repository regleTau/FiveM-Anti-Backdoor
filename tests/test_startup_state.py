
"""
tests/test_startup_state.py
Validates the startup state of the application.
Verifies that temporary scan/detection tables are reset on startup,
but persistent configurations, whitelist, and themes are preserved.
"""

import os
import unittest
import tempfile
from core import database as db
from main import init_app


class TestStartupState(unittest.TestCase):

    def setUp(self) -> None:
        db.init_database()
        # Seed the DB with some fake persistent settings
        db.set_setting("theme", "Light")
        db.set_setting("whitelisted_domains", ["safe-server.net"])
        
        # Seed the DB with some fake active scan results
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO resources (name, path, framework, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("stale_resource", "C:/fivem/stale_resource", "standalone", "2026-08-11", "2026-08-11")
        )
        conn.execute(
            "INSERT INTO detections (scan_id, resource_id, resource_name, file_path, rule_id, rule_name, severity, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, 1, "stale_resource", "C:/fivem/stale_resource/server.lua", "RULE-001", "Stale backdoor", "CRITICAL", 100, "2026-08-11")
        )
        conn.commit()
        conn.close()

    def test_startup_cleans_temporary_data(self) -> None:
        # Before init_app: detections and resources exist
        resources_before = db.get_all_resources()
        detections_before = db.get_all_detections()
        self.assertTrue(len(resources_before) > 0)
        self.assertTrue(len(detections_before) > 0)

        # Execute startup initialization
        init_app()

        # After init_app: active scanner tables must be clean
        resources_after = db.get_all_resources()
        detections_after = db.get_all_detections()
        self.assertEqual(len(resources_after), 0, "Active resource list must be clean on startup")
        self.assertEqual(len(detections_after), 0, "Active threats list must be clean on startup")

    def test_startup_preserves_persistent_data(self) -> None:
        init_app()

        # Check theme and whitelist are preserved
        self.assertEqual(db.get_setting("theme"), "Light")
        self.assertEqual(db.get_setting("whitelisted_domains"), ["safe-server.net"])

    def test_no_file_modification_on_startup(self) -> None:
        # Create a temp file simulating a resource file
        temp_dir = tempfile.TemporaryDirectory()
        dummy_file = os.path.join(temp_dir.name, "server.lua")
        with open(dummy_file, "w", encoding="utf-8") as f:
            f.write("print('hello')")
        
        mtime_before = os.path.getmtime(dummy_file)

        # Run startup initialization
        init_app()

        # Verify mtime is unchanged and file exists
        self.assertTrue(os.path.exists(dummy_file))
        self.assertEqual(os.path.getmtime(dummy_file), mtime_before, "Startup must never touch or modify user files")
        temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
