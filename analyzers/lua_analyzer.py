"""
analyzers/lua_analyzer.py
FiveM-specific Lua static analyzer.
Detects backdoors, suspicious patterns, and malicious code in Lua resources.
NEVER executes any Lua code.
"""

import re
import os
import json
from typing import List, Dict, Tuple, Optional

from core.risk_scorer import DetectionResult


# ─── Whitelisted framework patterns ─────────────────────────────────────────
# These reduce false positives for common legitimate FiveM frameworks.
FRAMEWORK_SAFE_PATTERNS = [
    "ESX.RegisterUsableItem",
    "ESX.SetPlayerData",
    "QBCore.Functions.GetPlayer",
    "exports['ox_lib']",
    "exports['qb-core']",
    "exports['es_extended']",
]

# Known benign domains for HTTP requests
SAFE_DOMAINS = [
    "cfx.re",
    "runtime.fivem.net",
    "github.com",
    "raw.githubusercontent.com",
    "forum.cfx.re",
]


def _load_signature_file(sig_path: str) -> List[Dict]:
    """Load a JSON signature file and return the rules list."""
    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rules", [])
    except Exception:
        return []


def _get_signatures_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "signatures")


def _get_code_context(lines: List[str], line_index: int, context: int = 3) -> str:
    start = max(0, line_index - context)
    end = min(len(lines), line_index + context + 1)
    ctx_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_index else "    "
        ctx_lines.append(f"{prefix}{i+1:4d} | {lines[i].rstrip()}")
    return "\n".join(ctx_lines)


def _is_commented(line: str) -> bool:
    """Check if a Lua line is a comment."""
    stripped = line.lstrip()
    return stripped.startswith("--")


def _find_pattern_hits(content: str, lines: List[str],
                       patterns: List[str]) -> List[Tuple[int, str, str]]:
    """
    Search for pattern strings in content lines.
    Returns list of (line_index, matched_text, line_content).
    """
    hits = []
    for pattern_str in patterns:
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
        except re.error:
            # Fall back to literal search
            compiled = None

        if compiled:
            for i, line in enumerate(lines):
                if _is_commented(line):
                    continue
                m = compiled.search(line)
                if m:
                    hits.append((i, m.group(0), line))
        else:
            for i, line in enumerate(lines):
                if _is_commented(line):
                    continue
                if pattern_str.lower() in line.lower():
                    hits.append((i, pattern_str, line))
    return hits


def _check_combination(content_lower: str, patterns: List[str]) -> bool:
    """Check if ALL patterns in a combination list appear anywhere in the content."""
    for pat in patterns:
        try:
            if not re.search(pat, content_lower, re.IGNORECASE | re.DOTALL):
                return False
        except re.error:
            if pat.lower() not in content_lower:
                return False
    return True


def _is_safe_domain(url: str) -> bool:
    for domain in SAFE_DOMAINS:
        if domain in url:
            return True
    return False


def _extract_url_from_line(line: str) -> Optional[str]:
    m = re.search(r"https?://[^\s'\")\]]+", line)
    return m.group(0) if m else None


# ─── Main analyzer ───────────────────────────────────────────────────────────

def analyze_lua_file(file_path: str, resource_name: str = "",
                     extra_rules: Optional[List[Dict]] = None) -> List[DetectionResult]:
    """
    Perform static analysis on a Lua file.

    Returns a list of DetectionResult objects.
    Never executes any Lua code.
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
    content_lower = content.lower()

    sig_dir = _get_signatures_dir()

    # Load signature files
    backdoor_rules = _load_signature_file(os.path.join(sig_dir, "fivem_backdoors.json"))
    suspicious_rules = _load_signature_file(os.path.join(sig_dir, "fivem_suspicious.json"))

    all_rules = backdoor_rules + suspicious_rules
    if extra_rules:
        all_rules.extend(extra_rules)

    # ── Process signature rules ────────────────────────────────────────────
    reported_rule_ids: set = set()

    for rule in all_rules:
        rule_id = rule.get("id", "UNKNOWN")
        file_types = rule.get("file_types", [])
        if file_types and "lua" not in file_types:
            continue
        if not rule.get("enabled", True):
            continue

        pattern_type = rule.get("pattern_type", "regex")
        patterns = rule.get("patterns", [])

        if pattern_type == "combination":
            # All patterns must appear in the file
            if _check_combination(content_lower, patterns):
                # Find the line of first pattern hit for line number
                first_line = None
                first_code_ctx = ""
                for pat in patterns:
                    try:
                        m = re.search(pat, content, re.IGNORECASE | re.DOTALL)
                    except re.error:
                        m = None
                    if m:
                        line_idx = content[:m.start()].count("\n")
                        if first_line is None:
                            first_line = line_idx + 1
                            first_code_ctx = _get_code_context(lines, line_idx)
                        break

                if rule_id not in reported_rule_ids:
                    reported_rule_ids.add(rule_id)
                    results.append(DetectionResult(
                        rule_id=rule_id,
                        rule_name=rule.get("name", "Unknown"),
                        severity=rule.get("severity", "MEDIUM"),
                        confidence=rule.get("confidence", 50),
                        description=rule.get("description", ""),
                        recommendation=rule.get("recommendation", ""),
                        file_path=file_path,
                        line_number=first_line,
                        code_context=first_code_ctx,
                        matched_pattern=" + ".join(patterns[:3]),
                        resource_name=resource_name,
                    ))

        elif pattern_type == "regex":
            hits = _find_pattern_hits(content, lines, patterns)
            for line_idx, matched, line_content in hits:
                if rule_id not in reported_rule_ids:
                    reported_rule_ids.add(rule_id)

                    # HTTP-specific: skip whitelisted domains
                    if "PerformHttpRequest" in matched or "PerformHttpRequest" in line_content:
                        url = _extract_url_from_line(line_content)
                        if url and _is_safe_domain(url):
                            continue

                    results.append(DetectionResult(
                        rule_id=rule_id,
                        rule_name=rule.get("name", "Unknown"),
                        severity=rule.get("severity", "MEDIUM"),
                        confidence=rule.get("confidence", 50),
                        description=rule.get("description", ""),
                        recommendation=rule.get("recommendation", ""),
                        file_path=file_path,
                        line_number=line_idx + 1,
                        code_context=_get_code_context(lines, line_idx),
                        matched_pattern=matched[:200],
                        resource_name=resource_name,
                    ))

    # ── Custom heuristic checks ────────────────────────────────────────────

    # 1. Suspicious RegisterNetEvent + AddEventHandler with no authz check (Disabled due to false positives)
    # _check_unprotected_events(lines, file_path, resource_name, results, reported_rule_ids)

    # 2. PerformHttpRequest with suspicious URL patterns (Disabled in favor of specific signature checks)
    # _check_suspicious_http(lines, file_path, resource_name, results, reported_rule_ids)

    # 3. TriggerClientEvent to all (-1) from net event handler
    _check_broadcast_trigger(content, lines, file_path, resource_name, results, reported_rule_ids)

    # 4. loadstring / load with dynamic content
    _check_dynamic_execution(content, lines, file_path, resource_name, results, reported_rule_ids)

    # 5. os.execute / io.popen
    _check_shell_execution(lines, file_path, resource_name, results, reported_rule_ids)

    # 6. Discord webhook
    _check_discord_webhook(lines, file_path, resource_name, results, reported_rule_ids)

    return results


def _check_unprotected_events(lines: List[str], file_path: str, resource_name: str,
                               results: List[DetectionResult], reported: set) -> None:
    """Detect RegisterNetEvent without permission checks in nearby AddEventHandler."""
    rule_id = "FIVEM-SUSP-001-H"
    if rule_id in reported:
        return

    net_events: List[int] = []
    handler_lines: List[int] = []
    auth_patterns = re.compile(
        r'IsPlayerAceAllowed|GetPlayerGroup|hasPermission|is_ace_allowed|player\.group|'
        r'ESX\.GetPlayerFromId|QBCore\.Functions\.GetPlayer|isAdmin|hasRole',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        if re.search(r'RegisterNetEvent\s*\(', line, re.IGNORECASE):
            net_events.append(i)
        if re.search(r'AddEventHandler\s*\(', line, re.IGNORECASE):
            handler_lines.append(i)

    # Check if event handlers exist without authorization patterns
    if net_events and not any(auth_patterns.search(l) for l in lines):
        # Only flag if there are actual handler implementations
        if handler_lines:
            results.append(DetectionResult(
                rule_id=rule_id,
                rule_name="Net Events Without Authorization",
                severity="LOW",
                confidence=40,
                description="Resource registers network events without apparent authorization/permission checks. "
                            "Ensure server-side validation is in place.",
                recommendation="Add IsPlayerAceAllowed() or framework-specific permission checks to all net event handlers.",
                file_path=file_path,
                line_number=net_events[0] + 1 if net_events else None,
                code_context=_get_code_context(lines, net_events[0]) if net_events else "",
                matched_pattern=f"{len(net_events)} RegisterNetEvent, {len(handler_lines)} AddEventHandler, no authz",
                resource_name=resource_name,
            ))
            reported.add(rule_id)


def _check_suspicious_http(lines: List[str], file_path: str, resource_name: str,
                            results: List[DetectionResult], reported: set) -> None:
    """Detect PerformHttpRequest calls with suspicious characteristics."""
    rule_id = "FIVEM-BACK-010-H"
    if rule_id in reported:
        return

    safe_domains = [
        "cfx.re", "runtime.fivem.net", "github.com", "raw.githubusercontent.com",
        "discord.com/api/webhooks",  # handled separately
    ]

    http_pattern = re.compile(r'PerformHttpRequest\s*\(', re.IGNORECASE)

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        if http_pattern.search(line):
            url = _extract_url_from_line(line)
            if url:
                # Check if it goes to a known-bad or unknown domain
                is_safe = any(d in url for d in safe_domains)
                is_discord = "discord.com/api/webhooks" in url

                if is_discord and "FIVEM-BACK-005" not in reported:
                    # Discord webhook is flagged by signature rules already
                    pass
                elif not is_safe:
                    if rule_id not in reported:
                        reported.add(rule_id)
                        results.append(DetectionResult(
                            rule_id=rule_id,
                            rule_name="HTTP Request to Unknown External Domain",
                            severity="MEDIUM",
                            confidence=60,
                            description=f"Makes an HTTP request to an unknown external domain: {url[:100]}",
                            recommendation="Verify this endpoint is legitimate and necessary.",
                            file_path=file_path,
                            line_number=i + 1,
                            code_context=_get_code_context(lines, i),
                            matched_pattern=url[:100],
                            resource_name=resource_name,
                        ))


def _check_broadcast_trigger(content: str, lines: List[str], file_path: str,
                               resource_name: str, results: List[DetectionResult],
                               reported: set) -> None:
    """Detect TriggerClientEvent to all players (-1) within server event handlers."""
    rule_id = "FIVEM-SUSP-005-H"
    if rule_id in reported:
        return

    broadcast_pattern = re.compile(
        r'TriggerClientEvent\s*\([^,]+,\s*-1', re.IGNORECASE
    )

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        m = broadcast_pattern.search(line)
        if m:
            if rule_id not in reported:
                reported.add(rule_id)
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Broadcast TriggerClientEvent (-1)",
                    severity="MEDIUM",
                    confidence=55,
                    description="Triggers a client event on ALL players using source=-1. "
                                "This can be abused to send malicious data to all clients.",
                    recommendation="Avoid broadcasting sensitive events to all players. Use targeted triggers.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern=m.group(0)[:100],
                    resource_name=resource_name,
                ))


def _check_dynamic_execution(content: str, lines: List[str], file_path: str,
                              resource_name: str, results: List[DetectionResult],
                              reported: set) -> None:
    """Detect loadstring/load() with dynamic/encoded content."""
    rule_id = "FIVEM-BACK-002-H"
    if rule_id in reported:
        return

    # loadstring( or load( not followed by 'file' or 'string' (resource file loading)
    loadstring_pattern = re.compile(
        r'\bloadstring\s*\(|(?<![A-Za-z_])load\s*\((?!\s*(?:ResourceFile|File|string\.format\s*\([^)]*%q))',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        if loadstring_pattern.search(line):
            if rule_id not in reported:
                reported.add(rule_id)
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Dynamic Code Execution (loadstring/load)",
                    severity="HIGH",
                    confidence=82,
                    description="Dynamically compiles and executes a string as Lua code via loadstring() or load().",
                    recommendation="Replace with static code. If necessary, ensure the string source is trusted and validated.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern=line.strip()[:100],
                    resource_name=resource_name,
                ))


def _check_shell_execution(lines: List[str], file_path: str, resource_name: str,
                            results: List[DetectionResult], reported: set) -> None:
    """Detect os.execute and io.popen shell execution."""
    rule_id = "FIVEM-BACK-003-H"
    if rule_id in reported:
        return

    shell_pattern = re.compile(r'os\.execute\s*\(|io\.popen\s*\(', re.IGNORECASE)

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        m = shell_pattern.search(line)
        if m:
            if rule_id not in reported:
                reported.add(rule_id)
                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Shell Command Execution",
                    severity="CRITICAL",
                    confidence=95,
                    description="Executes system shell commands via os.execute() or io.popen(). "
                                "FiveM resources must never execute OS commands.",
                    recommendation="Remove this code immediately. If functionality is required, use FiveM native functions.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern=m.group(0)[:100],
                    resource_name=resource_name,
                ))


def _check_discord_webhook(lines: List[str], file_path: str, resource_name: str,
                            results: List[DetectionResult], reported: set) -> None:
    """Detect Discord webhook usage that may be used for data exfiltration."""
    rule_id = "FIVEM-BACK-005-H"
    if rule_id in reported:
        return

    webhook_pattern = re.compile(
        r'discord\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+',
        re.IGNORECASE,
    )

    # Also check for generic webhook patterns
    generic_webhook = re.compile(
        r'discord(?:app)?\.com/api/webhooks',
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if _is_commented(line):
            continue
        if webhook_pattern.search(line) or generic_webhook.search(line):
            if rule_id not in reported:
                reported.add(rule_id)
                # Classify severity based on what's sent alongside webhook
                context_window = "\n".join(lines[max(0, i-10):min(len(lines), i+10)])
                severity = "MEDIUM"
                confidence = 65
                desc = "Sends data to a Discord webhook. Review what data is transmitted."

                sensitive_pattern = re.compile(
                    r'identifier|GetPlayerIdentifiers|license|steam|discord|ip|'
                    r'GetConvar|password|token|secret|key|credential',
                    re.IGNORECASE,
                )
                if sensitive_pattern.search(context_window):
                    severity = "HIGH"
                    confidence = 88
                    desc = "Sends potentially sensitive player/server data to a Discord webhook."

                results.append(DetectionResult(
                    rule_id=rule_id,
                    rule_name="Discord Webhook Data Transmission",
                    severity=severity,
                    confidence=confidence,
                    description=desc,
                    recommendation="Review all data sent to Discord webhooks. Remove if used for exfiltration.",
                    file_path=file_path,
                    line_number=i + 1,
                    code_context=_get_code_context(lines, i),
                    matched_pattern="discord.com/api/webhooks/...",
                    resource_name=resource_name,
                ))
