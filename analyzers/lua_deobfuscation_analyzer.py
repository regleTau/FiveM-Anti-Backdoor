"""
analyzers/lua_deobfuscation_analyzer.py
Wrapper extending standard Lua static analyzer to run checks on deobfuscated payload results.
"""

from typing import List
from core.risk_scorer import DetectionResult
from analyzers.lua_analyzer import analyze_lua_file


def analyze_deobfuscated_lua(file_path: str, resource_name: str) -> List[DetectionResult]:
    """Runs standard Lua analysis on deobfuscated content paths."""
    return analyze_lua_file(file_path, resource_name)
