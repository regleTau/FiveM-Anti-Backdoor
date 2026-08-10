"""
analyzers/obfuscation_analyzer.py
Static obfuscation detection for Lua and JavaScript files.
NEVER executes any code. Pure text/byte analysis only.
"""

import re
import os
import math
from typing import List, Optional
from core.risk_scorer import DetectionResult


# ─── Heuristics ──────────────────────────────────────────────────────────────

# Minimum length of a Base64 blob to flag
B64_MIN_LEN = 40

# Minimum line length to flag as "very long line"
LONG_LINE_THRESHOLD = 500

# Minimum hex sequence repetitions
HEX_SEQ_MIN = 8

# Minimum string.char() arguments to flag
STRCHAR_MIN_ARGS = 5

# Entropy threshold for obfuscation suspicion
HIGH_ENTROPY_THRESHOLD = 4.8  # bits per char


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _get_code_context(lines: List[str], line_index: int, context: int = 2) -> str:
    start = max(0, line_index - context)
    end = min(len(lines), line_index + context + 1)
    ctx_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_index else "    "
        ctx_lines.append(f"{prefix}{i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(ctx_lines)


def analyze_obfuscation(file_path: str, resource_name: str = "") -> List[DetectionResult]:
    """
    Analyze a file for obfuscation indicators.
    Returns a list of DetectionResult objects.
    """
    results: List[DetectionResult] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return results

    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    lines = content.splitlines()

    # ── 1. Lua bytecode header ─────────────────────────────────────────────
    if ext == ".lua":
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            if magic == b"\x1bLua":
                results.append(DetectionResult(
                    rule_id="LUA-OBF-009",
                    rule_name="Lua Bytecode Header",
                    severity="HIGH",
                    confidence=90,
                    description="File contains compiled Lua bytecode. Source code is hidden; this is highly suspicious.",
                    recommendation="Do not load this file. Decompile with luadec/unluac and inspect.",
                    file_path=file_path,
                    line_number=1,
                    code_context="[Binary Lua bytecode — cannot display]",
                    matched_pattern="\\x1bLua magic bytes",
                    resource_name=resource_name,
                ))
                return results  # No further text analysis on binary
        except Exception:
            pass

    # ── 2. Very long single lines ──────────────────────────────────────────
    for i, line in enumerate(lines):
        if len(line) > LONG_LINE_THRESHOLD:
            # Check entropy to reduce false positives
            entropy = _shannon_entropy(line[:200])
            confidence = min(90, 50 + int((len(line) - LONG_LINE_THRESHOLD) / 100) * 5)
            if entropy > HIGH_ENTROPY_THRESHOLD:
                confidence = min(95, confidence + 15)
            results.append(DetectionResult(
                rule_id="LUA-OBF-001",
                rule_name="Long Single-Line Code",
                severity="MEDIUM",
                confidence=confidence,
                description=f"Line {i+1} is {len(line)} characters long. Long single lines often indicate packed/obfuscated code.",
                recommendation="Manually inspect and deobfuscate this line.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern=f"Line length: {len(line)} chars",
                resource_name=resource_name,
            ))
            break  # Only report once per file

    # ── 3. Base64 blobs ───────────────────────────────────────────────────
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{' + str(B64_MIN_LEN) + r',}={0,2}')
    b64_hits = 0
    for i, line in enumerate(lines):
        for m in b64_pattern.finditer(line):
            blob = m.group(0)
            # Validate it's not just a SHA hash or variable name
            if len(blob) >= B64_MIN_LEN and len(blob) % 4 in (0, 2, 3):
                b64_hits += 1
                if b64_hits <= 2:  # Report up to 2 instances
                    results.append(DetectionResult(
                        rule_id="LUA-OBF-002",
                        rule_name="Base64 Encoded String",
                        severity="MEDIUM",
                        confidence=72,
                        description="Contains a Base64-encoded string that may conceal malicious payloads.",
                        recommendation="Decode the Base64 string and inspect its contents.",
                        file_path=file_path,
                        line_number=i + 1,
                        code_context=_get_code_context(lines, i),
                        matched_pattern=blob[:80] + ("..." if len(blob) > 80 else ""),
                        resource_name=resource_name,
                    ))

    # ── 4. Hex sequence payloads ──────────────────────────────────────────
    hex_pattern = re.compile(r'(?:0x[0-9a-fA-F]{2,}[\s,;]+){' + str(HEX_SEQ_MIN) + r',}')
    for i, line in enumerate(lines):
        if hex_pattern.search(line):
            results.append(DetectionResult(
                rule_id="LUA-OBF-003",
                rule_name="Hexadecimal String Payload",
                severity="MEDIUM",
                confidence=68,
                description="Contains a long hexadecimal sequence that may encode hidden data.",
                recommendation="Decode the hex data and inspect its contents.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern="Hex sequence detected",
                resource_name=resource_name,
            ))
            break

    # ── 5. string.char() with many args (Lua) ────────────────────────────
    if ext == ".lua":
        strchar_pattern = re.compile(
            r'string\.char\s*\((?:\s*\d+\s*,?\s*){' + str(STRCHAR_MIN_ARGS) + r',}\)'
        )
        for i, line in enumerate(lines):
            if strchar_pattern.search(line):
                results.append(DetectionResult(
                    rule_id="LUA-OBF-005",
                    rule_name="string.char() Obfuscation",
                    severity="MEDIUM",
                    confidence=75,
                    description="Uses string.char() with many numeric arguments to hide string content.",
                    recommendation="Evaluate the constructed string to inspect hidden content.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern="string.char(...)",
                    resource_name=resource_name,
                ))
                break

    # ── 6. Escape-heavy string literals ──────────────────────────────────
    esc_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}){10,}')
    for i, line in enumerate(lines):
        if esc_pattern.search(line):
            results.append(DetectionResult(
                rule_id="LUA-OBF-007",
                rule_name="Escape-Heavy String Literal",
                severity="MEDIUM",
                confidence=65,
                description="Contains strings with excessive hex escape sequences, often used to hide code.",
                recommendation="Decode the escape sequences and inspect the resulting string.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern="\\xNN escape sequences",
                resource_name=resource_name,
            ))
            break

    # ── 7. XOR decode loop (Lua) ──────────────────────────────────────────
    if ext == ".lua":
        xor_pattern = re.compile(r'(?:bxor|bit\.bxor)', re.IGNORECASE)
        loop_pattern = re.compile(r'\b(?:for|while|repeat)\b')
        has_xor = False
        has_loop = False
        for i, line in enumerate(lines):
            if xor_pattern.search(line):
                has_xor = True
            if loop_pattern.search(line):
                has_loop = True
        if has_xor and has_loop:
            results.append(DetectionResult(
                rule_id="LUA-OBF-010",
                rule_name="XOR Decode Loop",
                severity="HIGH",
                confidence=80,
                description="Contains an XOR decoding loop, commonly used to decrypt hidden payloads.",
                recommendation="Manually trace and decode the XOR payload.",
                file_path=file_path,
                line_number=None,
                code_context="XOR + loop detected across multiple lines",
                matched_pattern="bxor / bit.bxor with loop",
                resource_name=resource_name,
            ))

    # ── 8. JavaScript Base64 (atob/btoa) ─────────────────────────────────
    if ext in {".js", ".mjs"}:
        atob_pattern = re.compile(r'\batob\s*\(|\bbtoa\s*\(')
        for i, line in enumerate(lines):
            if atob_pattern.search(line):
                results.append(DetectionResult(
                    rule_id="JS-SUSP-004",
                    rule_name="JavaScript atob/btoa Encoding",
                    severity="MEDIUM",
                    confidence=70,
                    description="Uses atob()/btoa() to encode/decode Base64 in NUI JavaScript.",
                    recommendation="Decode and inspect the Base64 content.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern="atob() / btoa()",
                    resource_name=resource_name,
                ))
                break

    # ── 9. Nested parenthesis (deep nesting indicator) ────────────────────
    for i, line in enumerate(lines):
        if "(((((" in line:
            depth = max(
                sum(1 for c in line if c == "(") - sum(1 for c in line if c == ")"),
                line.count("((((("),
            )
            results.append(DetectionResult(
                rule_id="LUA-OBF-008",
                rule_name="Deeply Nested Function Calls",
                severity="MEDIUM",
                confidence=60,
                description="Deeply nested function calls often indicate layered obfuscation.",
                recommendation="Manually unwrap the nested functions and analyze each layer.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern="((((( ... nesting",
                resource_name=resource_name,
            ))
            break

    # ── 10. High-entropy file-level check ─────────────────────────────────
    if len(content) > 500:
        sample = content[:2000]
        entropy = _shannon_entropy(sample)
        if entropy > HIGH_ENTROPY_THRESHOLD and not any(
            r.rule_id in ("LUA-OBF-009", "LUA-OBF-001") for r in results
        ):
            confidence = min(85, int((entropy - HIGH_ENTROPY_THRESHOLD) * 30 + 50))
            results.append(DetectionResult(
                rule_id="LUA-OBF-HIGH-ENTROPY",
                rule_name="High Entropy Content",
                severity="LOW",
                confidence=confidence,
                description=f"File has high Shannon entropy ({entropy:.2f} bits/char), suggesting compressed or encrypted content.",
                recommendation="Inspect the file for encrypted payloads or compressed data.",
                file_path=file_path,
                line_number=None,
                code_context=f"File entropy: {entropy:.2f} bits/char",
                matched_pattern=f"entropy={entropy:.2f}",
                resource_name=resource_name,
            ))

    return results
