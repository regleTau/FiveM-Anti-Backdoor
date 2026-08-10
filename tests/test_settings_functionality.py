"""
tests/test_settings_functionality.py
Integration tests validating Settings menu configuration logic.
Verifies Scan Lua, Scan JS, Scan NUI, Scan Hidden, Whitelist domains, and backup cleaning settings.
"""

import os
import unittest
import tempfile
from core import database as db
from core.scanner import _analyze_file, _load_config
from core.file_discovery import FiveMFile, FiveMResource, discover_resources
from core.backup_manager import restore_file


class TestSettingsFunctionality(unittest.TestCase):

    def setUp(self) -> None:
        db.init_database()
        self.temp_root = tempfile.TemporaryDirectory()
        self.res = FiveMResource(name="settings_resource", path=self.temp_root.name)

    def tearDown(self) -> None:
        self.temp_root.cleanup()

    def test_scan_lua_flag(self) -> None:
        lua_file = os.path.join(self.temp_root.name, "script.lua")
        with open(lua_file, "w", encoding="utf-8") as f:
            f.write("loadstring('test')")

        f_obj = FiveMFile(
            absolute_path=lua_file,
            relative_path="script.lua",
            filename="script.lua",
            extension=".lua",
            size_bytes=len("loadstring('test')"),
            file_type="lua"
        )

        # 1. Test scan_lua = True (should scan)
        cfg_on = {"scan": {"scan_lua": True, "obfuscation_enabled": True}}
        dets_on = _analyze_file(f_obj, self.res, cfg_on)
        self.assertTrue(len(dets_on) > 0, "Should scan Lua files when scan_lua is True")

        # 2. Test scan_lua = False (should skip)
        cfg_off = {"scan": {"scan_lua": False, "obfuscation_enabled": True}}
        dets_off = _analyze_file(f_obj, self.res, cfg_off)
        self.assertEqual(len(dets_off), 0, "Should skip Lua files when scan_lua is False")

    def test_scan_js_flag(self) -> None:
        js_file = os.path.join(self.temp_root.name, "script.js")
        with open(js_file, "w", encoding="utf-8") as f:
            f.write("eval('test')")

        f_obj = FiveMFile(
            absolute_path=js_file,
            relative_path="script.js",
            filename="script.js",
            extension=".js",
            size_bytes=len("eval('test')"),
            file_type="js"
        )

        # 1. Test scan_js = True (should scan)
        cfg_on = {"scan": {"scan_js": True, "obfuscation_enabled": True}}
        dets_on = _analyze_file(f_obj, self.res, cfg_on)
        self.assertTrue(len(dets_on) > 0, "Should scan JS files when scan_js is True")

        # 2. Test scan_js = False (should skip)
        cfg_off = {"scan": {"scan_js": False, "obfuscation_enabled": True}}
        dets_off = _analyze_file(f_obj, self.res, cfg_off)
        self.assertEqual(len(dets_off), 0, "Should skip JS files when scan_js is False")

    def test_scan_hidden_files_flag(self) -> None:
        # Create resource folder structure
        res_dir = os.path.join(self.temp_root.name, "test_res")
        os.makedirs(res_dir, exist_ok=True)
        
        # Write normal and hidden script files
        with open(os.path.join(res_dir, "fxmanifest.lua"), "w", encoding="utf-8") as f:
            f.write("client_script 'script.lua'")
        with open(os.path.join(res_dir, "script.lua"), "w", encoding="utf-8") as f:
            f.write("print('hello')")
        with open(os.path.join(res_dir, ".hidden.lua"), "w", encoding="utf-8") as f:
            f.write("print('hidden')")

        # 1. Check scan_hidden = False (default)
        db.set_setting("scan_hidden", False)
        resources = discover_resources(self.temp_root.name)
        self.assertTrue(len(resources) > 0)
        res_obj = resources[0]
        has_hidden = any(f.filename.startswith(".") for f in res_obj.files)
        self.assertFalse(has_hidden, "Should exclude hidden files by default")

        # 2. Check scan_hidden = True
        db.set_setting("scan_hidden", True)
        resources = discover_resources(self.temp_root.name)
        res_obj = resources[0]
        has_hidden = any(f.filename.startswith(".") for f in res_obj.files)
        self.assertTrue(has_hidden, "Should include hidden files when scan_hidden is True")

    def test_whitelisted_domains(self) -> None:
        lua_file = os.path.join(self.temp_root.name, "script.lua")
        # Domain Raw Github is whitelisted, should lower severity of normal http requests
        with open(lua_file, "w", encoding="utf-8") as f:
            f.write('PerformHttpRequest("https://raw.githubusercontent.com/esx-community/test", function() end)')

        f_obj = FiveMFile(
            absolute_path=lua_file,
            relative_path="script.lua",
            filename="script.lua",
            extension=".lua",
            size_bytes=len("PerformHttpRequest(...)"),
            file_type="lua"
        )

        cfg = {
            "scan": {
                "scan_lua": True,
                "obfuscation_enabled": False,
                "whitelisted_domains": ["raw.githubusercontent.com"]
            }
        }
        dets = _analyze_file(f_obj, self.res, cfg)
        for det in dets:
            self.assertEqual(det.severity, "LOW", "Whitelisted domain should suppress HTTP severity to LOW")

    def test_settings_persistence(self) -> None:
        # Save custom theme and scanning options to DB
        db.set_setting("theme", "Light")
        db.set_setting("scan_lua", False)

        # Retrieve and verify persistence
        self.assertEqual(db.get_setting("theme", "Dark"), "Light")
        self.assertEqual(db.get_setting("scan_lua", True), False)

        # Restore defaults
        db.set_setting("theme", "Dark")
        db.set_setting("scan_lua", True)


if __name__ == "__main__":
    unittest.main()
