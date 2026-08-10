"""
tests/test_functional.py
Complete functional and integration tests for FiveM Anti-Backdoor.
Verifies discovery, static analysis parsing, signatures matching, code cleaner (backup/modify/restore),
and confirms no execution of code.
"""

import os
import shutil
import tempfile
import unittest
import hashlib
from typing import Dict, List

from core import database as db
from core.file_discovery import discover_resources
from core.scanner import run_full_scan, _analyze_file
from core.risk_scorer import ResourceScanResult, DetectionResult
from core.change_detector import compute_sha256
from core.backup_manager import backup_file, restore_file
from analyzers.lua_analyzer import analyze_lua_file
from analyzers.js_analyzer import analyze_js_file
from analyzers.manifest_analyzer import analyze_manifest


# ─── Synthetic Files Content Definitions ─────────────────────────────────────

CLEAN_LUA = """
-- Clean Lua file
local ped = PlayerPedId()
if DoesEntityExist(ped) then
    TriggerServerEvent("server:onPlayerLoad")
end
"""

BAD_LUA = """
-- Suspicious Lua file containing a dynamic loader
RegisterNetEvent("loadCode")
AddEventHandler("loadCode", function(remoteUrl)
    PerformHttpRequest(remoteUrl, function(code, text)
        local load_fn = loadstring(text)
        if load_fn then
            load_fn()
        end
    end)
end)
"""

CLEAN_JS = """
// Clean JavaScript
window.addEventListener('message', (event) => {
    if (event.data.action === 'showUI') {
        document.body.style.display = 'block';
    }
});
"""

BAD_JS = """
// Suspicious JavaScript
window.addEventListener('message', (event) => {
    if (event.data.action === 'eval') {
        const payload = event.data.payload;
        eval(payload); // Suspicious eval usage
    }
});
"""

BAD_MANIFEST = """
fx_version 'cerulean'
game 'gta5'

-- Dangerous executable resource file declaration
file 'binaries/updater.exe'
files {
    'binaries/updater.exe'
}
"""


class TestFunctionalSystem(unittest.TestCase):

    def setUp(self) -> None:
        db.init_database()
        
        # Create a temp directory for resource scanning simulating resources/
        self.temp_root = tempfile.TemporaryDirectory()
        self.resources_dir = os.path.normpath(self.temp_root.name)
        db.set_setting("safe_workspace_root", self.resources_dir)

        # 1. Clean Lua resource
        self.clean_lua_dir = os.path.join(self.resources_dir, "clean_lua")
        os.makedirs(self.clean_lua_dir, exist_ok=True)
        self._write_file(os.path.join(self.clean_lua_dir, "fxmanifest.lua"), "fx_version 'cerulean'\ngame 'gta5'\nserver_script 'server.lua'")
        self._write_file(os.path.join(self.clean_lua_dir, "server.lua"), CLEAN_LUA)

        # 2. Suspicious Lua resource
        self.bad_lua_dir = os.path.join(self.resources_dir, "suspicious_lua")
        os.makedirs(self.bad_lua_dir, exist_ok=True)
        self._write_file(os.path.join(self.bad_lua_dir, "fxmanifest.lua"), "fx_version 'cerulean'\ngame 'gta5'\nserver_script 'server.lua'")
        self._write_file(os.path.join(self.bad_lua_dir, "server.lua"), BAD_LUA)

        # 3. Clean JS resource
        self.clean_js_dir = os.path.join(self.resources_dir, "clean_js")
        os.makedirs(self.clean_js_dir, exist_ok=True)
        self._write_file(os.path.join(self.clean_js_dir, "fxmanifest.lua"), "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfile 'html/script.js'")
        self._write_file(os.path.join(self.clean_js_dir, "html/script.js"), CLEAN_JS)

        # 4. Suspicious JS resource
        self.bad_js_dir = os.path.join(self.resources_dir, "suspicious_js")
        os.makedirs(self.bad_js_dir, exist_ok=True)
        self._write_file(os.path.join(self.bad_js_dir, "fxmanifest.lua"), "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfile 'html/script.js'")
        self._write_file(os.path.join(self.bad_js_dir, "html/script.js"), BAD_JS)

        # 5. Suspicious manifest resource
        self.bad_manifest_dir = os.path.join(self.resources_dir, "suspicious_manifest")
        os.makedirs(self.bad_manifest_dir, exist_ok=True)
        self._write_file(os.path.join(self.bad_manifest_dir, "fxmanifest.lua"), BAD_MANIFEST)

    def tearDown(self) -> None:
        self.temp_root.cleanup()

    def _write_file(self, path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def test_discovery_and_static_analysis(self) -> None:
        # Verify scanner discovers all resources
        resources = discover_resources(self.resources_dir)
        self.assertEqual(len(resources), 5, "Should discover exactly 5 FiveM resources")

        # Run scanner static engine
        results = run_full_scan(self.resources_dir)

        # Check clean lua resource has no threats
        clean_lua_res = next(r for r in results if r.resource_name == "clean_lua")
        self.assertEqual(len(clean_lua_res.detections), 0, "Clean Lua resource should have 0 detections")
        self.assertEqual(clean_lua_res.risk_score, 0)
        self.assertEqual(clean_lua_res.risk_level, "SAFE")

        # Check clean JS resource has no threats
        clean_js_res = next(r for r in results if r.resource_name == "clean_js")
        self.assertEqual(len(clean_js_res.detections), 0, "Clean JS resource should have 0 detections")

        # Check suspicious Lua resource detection
        bad_lua_res = next(r for r in results if r.resource_name == "suspicious_lua")
        self.assertTrue(len(bad_lua_res.detections) > 0, "Suspicious Lua should have detections")
        
        # Verify specific rules and contexts
        loadstring_det = next(d for d in bad_lua_res.detections if "loadstring" in d.rule_id or "FIVEM-BACK-001" in d.rule_id or "FIVEM-BACK-002-H" in d.rule_id)
        self.assertEqual(os.path.basename(loadstring_det.file_path), "server.lua")
        self.assertTrue(loadstring_det.line_number > 0)
        self.assertTrue(loadstring_det.confidence > 50)
        self.assertEqual(loadstring_det.severity, "CRITICAL")
        self.assertTrue(">>>" in loadstring_det.code_context or "loadstring" in loadstring_det.code_context)

        # Check suspicious JS resource detection
        bad_js_res = next(r for r in results if r.resource_name == "suspicious_js")
        self.assertTrue(len(bad_js_res.detections) > 0, "Suspicious JS should have detections")
        eval_det = next(d for d in bad_js_res.detections if "JS-SUSP-001" in d.rule_id)
        self.assertEqual(os.path.basename(eval_det.file_path), "script.js")
        self.assertEqual(eval_det.severity, "HIGH")

        # Check suspicious manifest resource detection
        bad_manifest_res = next(r for r in results if r.resource_name == "suspicious_manifest")
        self.assertTrue(len(bad_manifest_res.detections) > 0, "Suspicious manifest should have detections")
        exe_det = next(d for d in bad_manifest_res.detections if "MANIFEST-006" in d.rule_id)
        self.assertEqual(exe_det.severity, "CRITICAL")

    def test_safe_cleaner_and_backup_restore(self) -> None:
        target_file = os.path.join(self.bad_lua_dir, "server.lua")
        orig_hash = compute_sha256(target_file)
        self.assertIsNotNone(orig_hash)

        # 1. Create backup
        backup_path = backup_file(target_file, "suspicious_lua", reason="Test safe cleaner")
        self.assertIsNotNone(backup_path)

        # 2. Modify target (Safe clean action)
        with open(target_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Modify the line containing loadstring
        modified = False
        for i, line in enumerate(lines):
            if "loadstring" in line:
                lines[i] = "-- [SAFE CLEANED] " + line
                modified = True

        self.assertTrue(modified, "Should modify the bad line")
        with open(target_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # 3. Verify target file actually changed
        new_hash = compute_sha256(target_file)
        self.assertNotEqual(orig_hash, new_hash)

        # 4. Re-scan the file to verify detection is gone
        results = analyze_lua_file(target_file, resource_name="suspicious_lua")
        loadstring_still_detected = any("loadstring" in r.rule_id for r in results)
        self.assertFalse(loadstring_still_detected, "Loadstring detection should be gone")

        # 5. Restore original file
        restore_success = restore_file(backup_path, target_file)
        self.assertTrue(restore_success)

        # 6. Verify restored file SHA-256 matches exactly the original SHA-256
        restored_hash = compute_sha256(target_file)
        self.assertEqual(orig_hash, restored_hash, "Restored file hash must match original file hash exactly")

    def test_static_only_guarantee(self) -> None:
        # Add side effects indicator to BAD_LUA code
        sentinel_path = os.path.join(self.temp_root.name, "side_effect.txt")
        active_lua_code = f"""
        -- If executed, this writes to a sentinel file
        local f = io.open("{sentinel_path.replace(os.sep, '/')}", "w")
        if f then
            f:write("Executed!")
            f:close()
        end
        """
        lua_file = os.path.join(self.clean_lua_dir, "active.lua")
        self._write_file(lua_file, active_lua_code)

        # Run static analyzer over it
        analyze_lua_file(lua_file, resource_name="clean_lua")

        # Confirm that the script was NEVER executed (sentinel file does not exist)
        self.assertFalse(os.path.exists(sentinel_path), "The scanner must never execute target script code!")


if __name__ == "__main__":
    unittest.main()
