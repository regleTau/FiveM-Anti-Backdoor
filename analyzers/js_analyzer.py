"""
analyzers/js_analyzer.py
FiveM NUI JavaScript static analyzer.
Detects suspicious patterns in NUI HTML/JS resources.
NEVER executes any JavaScript code.
"""

import re
import os
import json
from typing import List, Dict, Optional

from core.risk_scorer import DetectionResult


SAFE_DOMAINS = [
    "cfx.re",
    "runtime.fivem.net",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
]


def _get_signatures_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "signatures")


def _load_sig(sig_path: str) -> List[Dict]:
    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            return json.load(f).get("rules", [])
    except Exception:
        return []


def _is_js_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith("//") or s.startswith("*") or s.startswith("/*")


def _get_code_context(lines: List[str], line_index: int, context: int = 3) -> str:
    start = max(0, line_index - context)
    end = min(len(lines), line_index + context + 1)
    ctx = []
    for i in range(start, end):
        prefix = ">>> " if i == line_index else "    "
        ctx.append(f"{prefix}{i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(ctx)


def analyze_js_file(file_path: str, resource_name: str = "") -> List[DetectionResult]:
    """
    Perform static analysis on a JavaScript/NUI HTML file.
    Returns DetectionResult list. Never executes any code.
    """
    results: List[DetectionResult] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return results

    if not content.strip():
        return results

    lines = content.splitlines()
    ext = os.path.splitext(file_path)[1].lower()

    sig_dir = _get_signatures_dir()
    js_rules = _load_sig(os.path.join(sig_dir, "javascript_suspicious.json"))

    reported: set = set()

    # ── Process signature rules ────────────────────────────────────────────
    for rule in js_rules:
        rule_id = rule.get("id", "UNKNOWN")
        file_types = rule.get("file_types", [])
        ext_check = ext.lstrip(".")
        if file_types and ext_check not in file_types and ext not in [".html", ".htm"]:
            continue

        patterns = rule.get("patterns", [])
        pattern_type = rule.get("pattern_type", "regex")

        if pattern_type == "regex":
            for pat in patterns:
                try:
                    compiled = re.compile(pat, re.IGNORECASE)
                except re.error:
                    continue
                for i, line in enumerate(lines):
                    if _is_js_comment(line):
                        continue
                    m = compiled.search(line)
                    if m and rule_id not in reported:
                        reported.add(rule_id)
                        results.append(DetectionResult(
                            rule_id=rule_id,
                            rule_name=rule.get("name", "Unknown"),
                            severity=rule.get("severity", "MEDIUM"),
                            confidence=rule.get("confidence", 50),
                            description=rule.get("description", ""),
                            recommendation=rule.get("recommendation", ""),
                            file_path=file_path,
                            line_number=i + 1,
                            code_context=_get_code_context(lines, i),
                            matched_pattern=m.group(0)[:200],
                            resource_name=resource_name,
                        ))
                        break

    # ── Heuristic checks ───────────────────────────────────────────────────

    _check_eval(lines, file_path, resource_name, results, reported)
    _check_external_scripts(lines, file_path, resource_name, results, reported, ext)
    _check_websockets(lines, file_path, resource_name, results, reported)
    _check_external_fetch(lines, file_path, resource_name, results, reported)
    _check_post_message_leak(lines, file_path, resource_name, results, reported)
    _check_function_constructor(lines, file_path, resource_name, results, reported)

    return results


def _check_eval(lines: List[str], file_path: str, resource_name: str,
                results: List[DetectionResult], reported: set) -> None:
    rule_id = "JS-SUSP-001-H"
    if rule_id in reported:
        return
    eval_pattern = re.compile(r'\beval\s*\(', re.IGNORECASE)
    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        if eval_pattern.search(line):
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="eval() Dynamic Code Execution",
                severity="HIGH",
                confidence=85,
                description="Uses eval() to execute dynamic JavaScript code in NUI.",
                recommendation="Remove eval() and use safe, static alternatives.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern="eval(...)",
                resource_name=resource_name,
            ))
            break


def _check_external_scripts(lines: List[str], file_path: str, resource_name: str,
                              results: List[DetectionResult], reported: set,
                              ext: str) -> None:
    """Detect dynamic external script injection."""
    rule_id = "JS-SUSP-003-H"
    if rule_id in reported:
        return

    # Pattern: createElement('script') + setAttribute/src with external URL
    script_create = re.compile(
        r"createElement\s*\(\s*['\"]script['\"]", re.IGNORECASE
    )
    external_src = re.compile(
        r"(?:src|setAttribute)\s*[=\(]\s*['\"]https?://(?!" + "|".join(
            re.escape(d) for d in SAFE_DOMAINS
        ) + r")",
        re.IGNORECASE,
    )

    has_create = False
    has_ext_src = False
    create_line = 0

    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        if script_create.search(line):
            has_create = True
            create_line = i
        if external_src.search(line):
            has_ext_src = True

    if has_create and has_ext_src:
        reported.add(rule_id)
        results.append(DetectionResult(
            rule_id=rule_id,
            rule_name="Dynamic External Script Injection",
            severity="HIGH",
            confidence=80,
            description="Dynamically creates and loads an external script element, potentially introducing malicious code.",
            recommendation="Remove dynamic external script loading. All scripts should be bundled locally.",
            file_path=file_path,
            line_number=create_line + 1,
            code_context=_get_code_context(lines, create_line),
            matched_pattern="createElement('script') + external src",
            resource_name=resource_name,
        ))


def _check_websockets(lines: List[str], file_path: str, resource_name: str,
                       results: List[DetectionResult], reported: set) -> None:
    rule_id = "JS-SUSP-006-H"
    if rule_id in reported:
        return

    ws_pattern = re.compile(
        r"new\s+WebSocket\s*\(\s*['\"]wss?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        m = ws_pattern.search(line)
        if m:
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="External WebSocket Connection",
                severity="HIGH",
                confidence=78,
                description="Opens a WebSocket connection to an external host. "
                            "NUI resources should not establish external WebSocket connections.",
                recommendation="Remove external WebSocket connections from NUI resources.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern=m.group(0)[:100],
                resource_name=resource_name,
            ))
            break


def _check_external_fetch(lines: List[str], file_path: str, resource_name: str,
                           results: List[DetectionResult], reported: set) -> None:
    """Detect fetch() calls to external URLs."""
    rule_id = "JS-SUSP-005-H"
    if rule_id in reported:
        return

    fetch_pattern = re.compile(
        r"""fetch\s*\(\s*['"]https?://(?!localhost|127\.0\.0\.1)""",
        re.IGNORECASE,
    )
    xhr_pattern = re.compile(r'new\s+XMLHttpRequest\s*\(', re.IGNORECASE)

    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        m = fetch_pattern.search(line) or xhr_pattern.search(line)
        if m:
            url_match = re.search(r"https?://[^\s'\")\]]+", line)
            url = url_match.group(0) if url_match else "unknown"
            is_safe = any(d in url for d in SAFE_DOMAINS)
            if not is_safe:
                reported.add(rule_id)
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="External HTTP Request from NUI",
                    severity="MEDIUM",
                    confidence=65,
                    description=f"NUI JavaScript makes HTTP request to external URL: {url[:80]}",
                    recommendation="NUI should only communicate with the game via window.invokeNative / PostMessage. "
                                   "Remove external HTTP calls.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern=url[:100],
                    resource_name=resource_name,
                ))
                break


def _check_post_message_leak(lines: List[str], file_path: str, resource_name: str,
                               results: List[DetectionResult], reported: set) -> None:
    """Detect window.postMessage sending to external origins."""
    rule_id = "JS-NUI-PM-001"
    if rule_id in reported:
        return

    pm_pattern = re.compile(
        r"window\.postMessage\s*\([^)]+,\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        m = pm_pattern.search(line)
        if m:
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="PostMessage Sent to External Origin",
                severity="MEDIUM",
                confidence=70,
                description="window.postMessage() sends data to an external origin, potentially leaking information.",
                recommendation="Restrict postMessage to same-origin or use '*' carefully.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern=m.group(0)[:100],
                resource_name=resource_name,
            ))
            break


def _check_function_constructor(lines: List[str], file_path: str, resource_name: str,
                                  results: List[DetectionResult], reported: set) -> None:
    rule_id = "JS-SUSP-002-H"
    if rule_id in reported:
        return

    fn_pattern = re.compile(r'new\s+Function\s*\(', re.IGNORECASE)

    for i, line in enumerate(lines):
        if _is_js_comment(line):
            continue
        if fn_pattern.search(line):
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="Function Constructor (Dynamic Code)",
                severity="HIGH",
                confidence=82,
                description="Uses new Function() constructor to execute dynamic JavaScript code.",
                recommendation="Remove new Function() usage. Use static function definitions.",
                file_path=file_path,
                line_number=i + 1,
                code_context=_get_code_context(lines, i),
                matched_pattern="new Function(...)",
                resource_name=resource_name,
            ))
            break
