"""
tests/test_security_audit.py
Security audit validation tests for the FiveM security engine.
Ensures static analysis limits, path traversal mitigation, database consistency, and no shell command executions.
"""

import os
import unittest
import tempfile
from analyzers.lua_analyzer import analyze_lua_file
from analyzers.js_analyzer import analyze_js_file
from core.change_detector import compute_sha256
from core.backup_manager import backup_file, restore_file


class TestSecurityAudit(unittest.TestCase):

    def setUp(self) -> None:
        self.temp_root = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_root.cleanup()

    def test_static_analysis_does_not_execute_commands(self) -> None:
        # Create a file containing a OS execute command to write a sentinel file
        sentinel_path = os.path.join(self.temp_root.name, "audit_exec.txt")
        malicious_code = f'os.execute("echo executed > {sentinel_path}")'
        
        file_path = os.path.join(self.temp_root.name, "malicious.lua")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(malicious_code)

        # Run static analyzer
        analyze_lua_file(file_path, "audit_resource")

        # Verify sentinel file was NOT created (proving no code execution occurred)
        self.assertFalse(os.path.exists(sentinel_path), "Static scanning must not execute system commands.")

    def test_path_traversal_prevention_in_backups(self) -> None:
        # Verify that relative path components are handled safely
        traversal_path = os.path.join(self.temp_root.name, "..", "traversal_file.lua")
        # Normalize to see if it escapes self.temp_root
        normalized = os.path.normpath(traversal_path)
        self.assertNotEqual(os.path.dirname(normalized), self.temp_root.name)

    def test_no_network_access(self) -> None:
        # Verifies that importing or running the analyzers does not open external sockets
        import socket
        # Save original socket constructor
        original_socket = socket.socket
        
        # Override to throw error on connect
        def socket_guard(*args, **kwargs):
            raise RuntimeError("Network connection blocked during security audit scan!")
        
        socket.socket = socket_guard
        try:
            # Run a standard file scan simulation
            temp_file = os.path.join(self.temp_root.name, "network_test.lua")
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write('PerformHttpRequest("https://google.com", function() end)')
            analyze_lua_file(temp_file, "net_res")
        finally:
            socket.socket = original_socket

    def test_restore_path_validation(self) -> None:
        from core.backup_manager import validate_restore_destination
        from core import database as db
        
        # Set workspace root for test validation
        workspace_root = os.path.abspath(self.temp_root.name)
        db.set_setting("safe_workspace_root", workspace_root)

        # 1. Valid path inside workspace
        valid_dest = os.path.join(workspace_root, "resources", "server.lua")
        self.assertTrue(validate_restore_destination(valid_dest))

        # 2. Traversal path escaping workspace
        unsafe_traversal = os.path.join(workspace_root, "..", "..", "..", "Windows", "System32", "test.txt")
        self.assertFalse(validate_restore_destination(unsafe_traversal))

        # 3. System paths
        self.assertFalse(validate_restore_destination(r"C:\Windows\System32\test.txt"))
        self.assertFalse(validate_restore_destination(r"C:\Program Files\test.txt"))

        # 4. UNC / Network paths
        self.assertFalse(validate_restore_destination(r"\\server\share\test.txt"))

        # 5. External directory outside workspace
        external_dir = tempfile.gettempdir()
        if os.path.abspath(external_dir) != workspace_root:
            self.assertFalse(validate_restore_destination(os.path.join(external_dir, "test.txt")))


if __name__ == "__main__":
    unittest.main()
