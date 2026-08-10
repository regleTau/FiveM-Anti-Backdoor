"""
core/source_mapper.py
Tracks positions of deobfuscated strings and maps threat line numbers
back to the original file's line numbers.
"""

from typing import Dict, Any, List, Optional


class SourceMapper:
    """Maps lines and strings from deobfuscated/decrypted space back to the original code."""

    def __init__(self, original_content: str, recovered_content: str) -> None:
        self.original_content = original_content
        self.recovered_content = recovered_content
        self.original_lines = original_content.splitlines()
        self.recovered_lines = recovered_content.splitlines()

    def map_line(self, recovered_line_num: int) -> Dict[str, Any]:
        """
        Attempt to resolve a recovered line back to its original line.
        Returns a dict containing original line, matched code, and reliability.
        """
        if recovered_line_num < 1 or recovered_line_num > len(self.recovered_lines):
            return {
                "original_line_number": -1,
                "reliable": False,
                "reason": "Line index out of recovered bounds",
            }

        recovered_line = self.recovered_lines[recovered_line_num - 1].strip()

        # Try to find the exact same text or string snippet in original lines
        matches = []
        for idx, orig_line in enumerate(self.original_lines):
            if recovered_line in orig_line or (len(recovered_line) > 10 and recovered_line[:20] in orig_line):
                matches.append(idx + 1)

        if len(matches) == 1:
            return {
                "original_line_number": matches[0],
                "reliable": True,
                "original_content": self.original_lines[matches[0] - 1],
            }
        elif len(matches) > 1:
            # Ambiguous mapping
            return {
                "original_line_number": matches[0],
                "reliable": False,
                "reason": "Ambiguous matches found in multiple original lines",
                "possible_lines": matches,
            }

        # Fuzzy mapping: search for fragments (e.g. variable names or unique strings)
        words = [w for w in recovered_line.split() if len(w) > 4 and w.isalnum()]
        for idx, orig_line in enumerate(self.original_lines):
            if any(word in orig_line for word in words):
                return {
                    "original_line_number": idx + 1,
                    "reliable": False,
                    "reason": "Fuzzy mapping match",
                }

        return {
            "original_line_number": -1,
            "reliable": False,
            "reason": "Could not map line safely back to obfuscated original file structure",
        }
