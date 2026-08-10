"""
core/file_classifier.py
Performs static analysis to classify files based on printable ratio,
Shannon entropy, escaped characters, line length, and binary markers.
"""

import math
import re
from typing import Dict, Any


def calculate_entropy(content: bytes) -> float:
    """Calculate Shannon entropy of bytes (values between 0.0 and 8.0)."""
    if not content:
        return 0.0
    frequencies = {}
    for byte in content:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    entropy = 0.0
    total = len(content)
    for count in frequencies.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def classify_file(file_path: str) -> Dict[str, Any]:
    """
    Classify a file based on metrics.
    Returns a dict with classification, confidence, entropy, and markers.
    """
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except Exception:
        return {
            "classification": "UNKNOWN",
            "confidence": 0.0,
            "entropy": 0.0,
            "details": "Failed to read file",
        }

    if not raw:
        return {
            "classification": "TEXT",
            "confidence": 100.0,
            "entropy": 0.0,
            "details": "Empty file",
        }

    # Basic stats
    total_bytes = len(raw)
    null_bytes = raw.count(b"\x00")
    
    # Try decoding to check if it is readable text
    text_content = ""
    is_unicode = False
    try:
        text_content = raw.decode("utf-8")
        is_unicode = True
    except UnicodeDecodeError:
        try:
            text_content = raw.decode("latin-1")
        except Exception:
            pass

    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    printable_ratio = printable / total_bytes if total_bytes > 0 else 0.0
    entropy = calculate_entropy(raw)

    lines = text_content.splitlines() if text_content else []
    max_line_len = max(len(l) for l in lines) if lines else 0
    avg_line_len = sum(len(l) for l in lines) / len(lines) if lines else 0

    # Detection of obfuscation, encoding, encryption
    classification = "TEXT"
    confidence = 80.0
    markers = []

    # 1. Binary Check
    if null_bytes > 0 or printable_ratio < 0.3:
        classification = "BINARY"
        confidence = 95.0
        return {
            "classification": classification,
            "confidence": confidence,
            "entropy": round(entropy, 2),
            "printable_ratio": round(printable_ratio, 2),
            "max_line_length": max_line_len,
        }

    # 2. Encryption signature (Very high entropy, low printable ratio or completely unreadable text)
    if entropy > 7.7 and printable_ratio < 0.6:
        classification = "ENCRYPTED"
        confidence = 90.0
    # 3. Compression signature
    elif raw.startswith(b"\x1f\x8b") or raw.startswith(b"PK\x03\x04"):
        classification = "COMPRESSED"
        confidence = 99.0
    # 4. Obfuscation check (long lines, high escape ratio, heavy hex/unicode usage)
    else:
        escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-9]{3}", text_content))
        escape_ratio = escapes / len(text_content) if text_content else 0.0

        if escape_ratio > 0.05 or (max_line_len > 2000 and len(lines) < 10 and printable_ratio > 0.8):
            classification = "OBFUSCATED"
            confidence = min(99.0, 50.0 + escape_ratio * 400.0 if escape_ratio > 0 else 85.0)
        elif max_line_len > 1000 and len(lines) < 20:
            classification = "MINIFIED"
            confidence = 85.0
        # 5. Encoded payloads check (e.g. Base64 strings or hex tables)
        elif "Base64" in text_content or len(re.findall(r"[A-Za-z0-9+/]{80,}", text_content)) > 2:
            classification = "ENCODED"
            confidence = 80.0

    return {
        "classification": classification,
        "confidence": round(confidence, 1),
        "entropy": round(entropy, 2),
        "printable_ratio": round(printable_ratio, 2),
        "max_line_length": max_line_len,
        "avg_line_length": round(avg_line_len, 1),
    }
