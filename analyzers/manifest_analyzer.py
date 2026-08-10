"""
analyzers/manifest_analyzer.py
FiveM fxmanifest.lua / __resource.lua static analyzer.
Inspects manifest files for hidden scripts, remote URLs, suspicious dependencies,
and missing/non-existent file references.
NEVER executes any Lua code.
"""

import re
import os
import json
from typing import List, Dict, Optional

from core.risk_scorer import DetectionResult


def _get_signatures_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "signatures")


def _load_sig(path: str) -> List[Dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("rules", [])
    except Exception:
        return []


def _get_code_context(lines: List[str], line_index: int, context: int = 2) -> str:
    start = max(0, line_index - context)
    end = min(len(lines), line_index + context + 1)
    ctx = []
    for i in range(start, end):
        prefix = ">>> " if i == line_index else "    "
        ctx.append(f"{prefix}{i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(ctx)


def _extract_string_values(content: str, keyword: str) -> List[str]:
    """Extract string values from a manifest keyword declaration."""
    values = []
    # Block form: keyword { 'a', 'b' }
    block_re = re.compile(
        rf"{re.escape(keyword)}\s*\{{([^}}]*)}}",
        re.DOTALL | re.IGNORECASE,
    )
    for m in block_re.finditer(content):
        items = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
        values.extend(items)

    # Single value: keyword 'value' or keyword "value"
    single_re = re.compile(
        rf"{re.escape(keyword)}\s+['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )
    for m in single_re.finditer(content):
        values.append(m.group(1))

    return values


def analyze_manifest(file_path: str, resource_path: str,
                     resource_name: str = "") -> List[DetectionResult]:
    """
    Perform static analysis on a fxmanifest.lua or __resource.lua file.
    Returns list of DetectionResult objects.
    """
    results: List[DetectionResult] = []

    if not os.path.isfile(file_path):
        return results

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return results

    lines = content.splitlines()
    reported: set = set()
    sig_dir = _get_signatures_dir()
    manifest_rules = _load_sig(os.path.join(sig_dir, "fxmanifest_rules.json"))

    # ── 1. Remote URL in manifest ──────────────────────────────────────────
    remote_url_re = re.compile(
        r"['\"]https?://[^'\"]+['\"]",
        re.IGNORECASE,
    )
    for i, line in enumerate(lines):
        if line.lstrip().startswith("--"):
            continue
        m = remote_url_re.search(line)
        if m:
            url = m.group(0).strip("'\"")
            rule_id = "MANIFEST-002"
            
            # Check if this URL is part of a script loading directive
            is_script_loader = any(kw in line for kw in ["server_script", "client_script", "shared_script", "file"])
            severity = "CRITICAL" if is_script_loader else "LOW"
            confidence = 95 if is_script_loader else 30
            
            if rule_id not in reported:
                reported.add(rule_id)
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Remote URL in Manifest",
                    severity=severity,
                    confidence=confidence,
                    description=f"Manifest includes a remote URL: {url}. "
                                "If placed inside executable script/file loaders, this downloads malicious code at runtime.",
                    recommendation="Remove remote URLs from executable loading directives. Keep metadata domains clean.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern=url[:100],
                    resource_name=resource_name,
                ))

    # ── 2. Hidden/suspicious script names ────────────────────────────────
    all_scripts: List[str] = []
    for kw in ["server_script", "client_script", "shared_script",
               "server_scripts", "client_scripts", "shared_scripts"]:
        all_scripts.extend(_extract_string_values(content, kw))

    suspicious_script_re = re.compile(
        r"""(?:
            [a-f0-9]{8,}\.[a-z]+$     # hash-named files
            | \.min\.lua$              # minified lua
            | ^\.                      # hidden files
            | _{3,}                    # excessive underscores
        )""",
        re.VERBOSE | re.IGNORECASE,
    )

    for script in all_scripts:
        basename = os.path.basename(script)
        if suspicious_script_re.search(basename):
            rule_id = "MANIFEST-001"
            if rule_id not in reported:
                reported.add(rule_id)
                # Find line number
                line_num = None
                ctx = ""
                for i, line in enumerate(lines):
                    if script in line or basename in line:
                        line_num = i + 1
                        ctx = _get_code_context(lines, i)
                        break
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Suspicious Script Name in Manifest",
                    severity="HIGH",
                    confidence=75,
                    description=f"Manifest declares a script with a suspicious name: '{script}'",
                    recommendation="Rename files to descriptive names. Hash-named or hidden files are red flags.",
                    file_path=file_path,
                    line_number=line_num,
                    code_context=ctx,
                    matched_pattern=script,
                    resource_name=resource_name,
                ))

    # ── 3. Scripts referencing non-existent files ─────────────────────────
    for script in all_scripts:
        # Skip glob patterns and remote URLs
        if "*" in script or "http" in script.lower():
            continue
        script_abs = os.path.normpath(os.path.join(resource_path, script))
        if not os.path.exists(script_abs):
            rule_id = "MANIFEST-005"
            basename = os.path.basename(script)
            is_suspicious_name = bool(suspicious_script_re.search(basename))
            severity = "HIGH" if is_suspicious_name else "LOW"
            confidence = 85 if is_suspicious_name else 40
            
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="Manifest References Non-Existent File",
                severity=severity,
                confidence=confidence,
                description=f"Manifest declares script '{script}' but the file does not exist in the resource directory.",
                recommendation="Verify resource configuration integrity. Investigate if script name is obfuscated or hidden.",
                file_path=file_path,
                line_number=None,
                code_context=f"Script declared: {script}\nExpected at: {script_abs}",
                matched_pattern=script,
                resource_name=resource_name,
            ))

    # ── 4. Suspicious dependencies ────────────────────────────────────────
    dependencies = _extract_string_values(content, "dependency") + \
                   _extract_string_values(content, "dependencies")

    suspicious_dep_re = re.compile(
        r"(?:loader|injector|hook|patch|exploit|bypass|inject|shell|rootkit|backdoor)",
        re.IGNORECASE,
    )

    for dep in dependencies:
        if suspicious_dep_re.search(dep):
            rule_id = "MANIFEST-003"
            if rule_id not in reported:
                reported.add(rule_id)
                line_num = None
                ctx = ""
                for i, line in enumerate(lines):
                    if dep in line:
                        line_num = i + 1
                        ctx = _get_code_context(lines, i)
                        break
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Suspicious Dependency Name",
                    severity="MEDIUM",
                    confidence=60,
                    description=f"Resource depends on '{dep}' which has a suspicious name.",
                    recommendation="Verify this dependency is legitimate and trusted.",
                    file_path=file_path,
                    line_number=line_num,
                    code_context=ctx,
                    matched_pattern=dep,
                    resource_name=resource_name,
                ))

    # ── 5. Unusual file types included ────────────────────────────────────
    included_files = _extract_string_values(content, "files")
    dangerous_exts = {".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".com"}

    for inc_file in included_files:
        ext = os.path.splitext(inc_file)[1].lower()
        if ext in dangerous_exts:
            rule_id = "MANIFEST-006"
            if rule_id not in reported:
                reported.add(rule_id)
                line_num = None
                ctx = ""
                for i, line in enumerate(lines):
                    if inc_file in line:
                        line_num = i + 1
                        ctx = _get_code_context(lines, i)
                        break
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Dangerous File Type Included in Resource",
                    severity="CRITICAL",
                    confidence=90,
                    description=f"Manifest includes a potentially dangerous file type: '{inc_file}'",
                    recommendation="Remove executable or script file inclusions from FiveM resources.",
                    file_path=file_path,
                    line_number=line_num,
                    code_context=ctx,
                    matched_pattern=inc_file,
                    resource_name=resource_name,
                ))

    # ── 6. Dynamic script names (Lua expressions in script list) ─────────
    dynamic_script_re = re.compile(
        r"""(?:server_script|client_script|shared_script)\s*\{[^}]*\.\.|\+[^}]*\}""",
        re.DOTALL | re.IGNORECASE,
    )
    if dynamic_script_re.search(content):
        rule_id = "MANIFEST-DYNAMIC-001"
        if rule_id not in reported:
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="Dynamic Script Name in Manifest",
                severity="HIGH",
                confidence=80,
                description="Manifest contains dynamically constructed script paths using Lua string concatenation.",
                recommendation="Use static, hardcoded script paths in manifests.",
                file_path=file_path,
                line_number=None,
                code_context="Dynamic script path construction detected",
                matched_pattern="server/client/shared_script { .. concatenation }",
                resource_name=resource_name,
            ))

    # ── 7. Missing game/version fields (basic manifest validation) ────────
    has_game = bool(re.search(r'\bgame\b|\bfx_version\b', content, re.IGNORECASE))
    if not has_game and os.path.basename(file_path).lower() == "fxmanifest.lua":
        rule_id = "MANIFEST-INVALID-001"
        if rule_id not in reported:
            reported.add(rule_id)
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="Invalid or Incomplete fxmanifest.lua",
                severity="LOW",
                confidence=50,
                description="fxmanifest.lua is missing the 'game' or 'fx_version' declaration.",
                recommendation="Ensure the manifest has valid fx_version and game fields.",
                file_path=file_path,
                line_number=1,
                code_context=lines[0] if lines else "",
                matched_pattern="Missing fx_version / game",
                resource_name=resource_name,
            ))

    return results
