"""
core/deobfuscator.py
Implements safe static transformations (deobfuscation passes) on string content.
Runs up to 5 passes and logs each transformation step.
"""

import re
import base64
import urllib.parse
from typing import List, Tuple


def decode_hex_escapes(content: str) -> Tuple[str, bool]:
    """Replace \\xXX hex escapes with their ASCII representation."""
    modified = False
    
    def repl(match):
        nonlocal modified
        hex_val = match.group(1)
        try:
            char = bytes.fromhex(hex_val).decode("utf-8", errors="replace")
            # Only replace if printable/safe to avoid messing up binary data
            if char.isprintable() or char in "\r\n\t":
                modified = True
                return char
        except Exception:
            pass
        return match.group(0)

    pattern = r"\\x([0-9a-fA-F]{2})"
    new_content = re.sub(pattern, repl, content)
    return new_content, modified


def decode_unicode_escapes(content: str) -> Tuple[str, bool]:
    """Replace \\uXXXX unicode escapes with actual characters."""
    modified = False

    def repl(match):
        nonlocal modified
        uni_val = match.group(1)
        try:
            char = chr(int(uni_val, 16))
            if char.isprintable() or char in "\r\n\t":
                modified = True
                return char
        except Exception:
            pass
        return match.group(0)

    pattern = r"\\u([0-9a-fA-F]{4})"
    new_content = re.sub(pattern, repl, content)
    return new_content, modified


def decode_lua_escapes(content: str) -> Tuple[str, bool]:
    """Replace Lua decimal escapes like \\65 with their ASCII character."""
    modified = False

    def repl(match):
        nonlocal modified
        dec_val = match.group(1)
        try:
            val = int(dec_val)
            if 0 <= val <= 255:
                char = chr(val)
                if char.isprintable() or char in "\r\n\t":
                    modified = True
                    return char
        except Exception:
            pass
        return match.group(0)

    pattern = r"\\([0-9]{3})"
    new_content = re.sub(pattern, repl, content)
    return new_content, modified


def fold_string_concats(content: str) -> Tuple[str, bool]:
    """Fold string concatenations like "foo" .. "bar" or "foo" + "bar"."""
    modified = False

    # Lua style: 'foo' .. 'bar' or "foo" .. "bar"
    def repl_lua(match):
        nonlocal modified
        modified = True
        return f'"{match.group(1)}{match.group(2)}"'

    # JS style: "foo" + "bar"
    def repl_js(match):
        nonlocal modified
        modified = True
        return f'"{match.group(1)}{match.group(2)}"'

    # Lua concat
    lua_pattern = r'["\']([^"\']+)["\']\s*\.\.\s*["\']([^"\']+)["\']'
    new_content = re.sub(lua_pattern, repl_lua, content)
    
    # JS concat
    js_pattern = r'["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']'
    new_content = re.sub(js_pattern, repl_js, new_content)

    return new_content, modified


def decode_base64_payloads(content: str) -> Tuple[str, bool]:
    """Identify and decode Base64 encoded strings within content if they result in readable text."""
    modified = False
    
    def repl(match):
        nonlocal modified
        b64_str = match.group(1)
        # Pad if necessary
        padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded)
            # Verify if it is clean printable text
            decoded_text = decoded_bytes.decode("utf-8")
            printable_ratio = sum(1 for c in decoded_text if c.isprintable() or c in "\r\n\t") / len(decoded_text)
            if printable_ratio > 0.85:
                modified = True
                return f'"{decoded_text}"'
        except Exception:
            pass
        return match.group(0)

    # Find base64 strings between quotes of length >= 32
    pattern = r'["\']([a-zA-Z0-9+/=]{32,})["\']'
    new_content = re.sub(pattern, repl, content)
    return new_content, modified


def resolve_string_arrays(content: str) -> Tuple[str, bool]:
    """
    Resolve obfuscated string tables/arrays when declared simply.
    Example: local _0x12 = {'a', 'b'} print(_0x12[1]) -> print('a')
    """
    modified = False
    
    # Match array declarations: local name = { 'a', 'b', ... }
    # or const name = [ "a", "b", ... ]
    array_patterns = [
        # Lua tables
        r'(?:local\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{([^}]+)\}',
        # JS arrays
        r'(?:const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\[([^\]]+)\]'
    ]

    new_content = content
    for pattern in array_patterns:
        for match in re.finditer(pattern, new_content):
            name = match.group(1)
            elements_str = match.group(2)
            elements = re.findall(r'["\']([^"\']+)["\']', elements_str)
            if not elements:
                continue

            # Replace array element accesses
            # Lua: name[1], name[2] (1-indexed)
            # JS: name[0], name[1] (0-indexed)
            def repl_access(access_match):
                nonlocal modified
                idx = int(access_match.group(1))
                # Check for Lua (1-indexed) or JS (0-indexed) usage depending on index
                # We will handle both safely
                try:
                    if idx > 0 and idx <= len(elements):
                        modified = True
                        return f'"{elements[idx - 1]}"'
                    elif idx >= 0 and idx < len(elements):
                        modified = True
                        return f'"{elements[idx]}"'
                except Exception:
                    pass
                return access_match.group(0)

            # Match name[idx]
            access_pattern = rf'{re.escape(name)}\s*\[\s*([0-9]+)\s*\]'
            new_content = re.sub(access_pattern, repl_access, new_content)

    return new_content, modified


class StaticDeobfuscator:
    """Safe, multi-pass static deobfuscation engine."""

    def __init__(self, max_passes: int = 5) -> None:
        self.max_passes = max_passes

    def deobfuscate(self, content: str) -> Tuple[str, List[str]]:
        """
        Run static transformations up to max_passes.
        Returns (deobfuscated_content, log_messages).
        """
        current = content
        logs = []
        
        for pass_num in range(1, self.max_passes + 1):
            pass_modified = False
            
            # Unicode decoding
            current, mod = decode_unicode_escapes(current)
            if mod:
                logs.append(f"Pass {pass_num}: Decoded Unicode escapes")
                pass_modified = True

            # Hex decoding
            current, mod = decode_hex_escapes(current)
            if mod:
                logs.append(f"Pass {pass_num}: Decoded Hex escapes")
                pass_modified = True

            # Lua escapes
            current, mod = decode_lua_escapes(current)
            if mod:
                logs.append(f"Pass {pass_num}: Decoded Lua decimal escapes")
                pass_modified = True

            # Concat folding
            current, mod = fold_string_concats(current)
            if mod:
                logs.append(f"Pass {pass_num}: Folded string concatenations")
                pass_modified = True

            # Base64 strings
            current, mod = decode_base64_payloads(current)
            if mod:
                logs.append(f"Pass {pass_num}: Decoded Base64 string payloads")
                pass_modified = True

            # String arrays
            current, mod = resolve_string_arrays(current)
            if mod:
                logs.append(f"Pass {pass_num}: Resolved string array indexes")
                pass_modified = True

            if not pass_modified:
                break

        if not logs:
            logs.append("No obfuscation layers identified.")

        return current, logs
