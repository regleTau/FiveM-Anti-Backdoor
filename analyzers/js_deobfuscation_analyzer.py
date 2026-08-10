"""
analyzers/js_deobfuscation_analyzer.py
Wrapper extending standard JS static analyzer to run checks on deobfuscated payload results.
"""

from typing import List
from core.risk_scorer import DetectionResult
from analyzers.js_analyzer import analyze_js_file


def analyze_deobfuscated_js(file_path: str, resource_name: str) -> List[DetectionResult]:
    """Runs standard JS analysis on deobfuscated content paths."""
    return analyze_js_file(file_path, resource_name)
