"""
core/scanner.py
Main FiveM scan orchestrator.
Coordinates resource discovery, analysis, risk scoring, and database storage.
NEVER executes scanned code.
"""

import os
import time
import json
import threading
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass, field

from core import database as db
from core.file_discovery import (
    FiveMResource, FiveMFile,
    discover_resources, discover_single_resource, get_quick_scan_files,
)
from core.risk_scorer import (
    DetectionResult, ResourceScanResult,
    apply_risk_score, sort_detections_by_severity,
)
from core.change_detector import compute_sha256, detect_changes
from analyzers.lua_analyzer import analyze_lua_file
from analyzers.js_analyzer import analyze_js_file
from analyzers.manifest_analyzer import analyze_manifest
from analyzers.obfuscation_analyzer import analyze_obfuscation


def _load_config() -> Dict:
    try:
        from core import database as db
        db.init_database()
        return {
            "scan": {
                "scan_lua": db.get_setting("scan_lua", True),
                "scan_js": db.get_setting("scan_js", True),
                "scan_nui": db.get_setting("scan_nui", True),
                "scan_hidden": db.get_setting("scan_hidden", False),
                "obfuscation_enabled": db.get_setting("obfuscation_enabled", True),
                "change_detection_enabled": db.get_setting("change_detection_enabled", True),
                "whitelisted_domains": db.get_setting("whitelisted_domains", [
                    "github.com", "raw.githubusercontent.com", "cfx.re", "runtime.fivem.net"
                ]),
            },
            "security": {
                "backup_enabled": db.get_setting("backup_enabled", True),
                "quarantine_enabled": db.get_setting("quarantine_enabled", False),
                "confirm_enabled": db.get_setting("confirm_enabled", True),
            }
        }
    except Exception:
        return {
            "scan": {
                "scan_lua": True,
                "scan_js": True,
                "scan_nui": True,
                "scan_hidden": False,
                "obfuscation_enabled": True,
                "change_detection_enabled": True,
                "whitelisted_domains": ["github.com", "raw.githubusercontent.com", "cfx.re", "runtime.fivem.net"],
            },
            "security": {
                "backup_enabled": True,
                "quarantine_enabled": False,
                "confirm_enabled": True,
            }
        }


@dataclass
class ScanProgress:
    """Thread-safe progress tracker for a scan operation."""
    total_resources: int = 0
    scanned_resources: int = 0
    total_files: int = 0
    scanned_files: int = 0
    current_resource: str = ""
    current_file: str = ""
    is_running: bool = False
    is_cancelled: bool = False
    total_detections: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **kwargs) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    @property
    def percent(self) -> int:
        if self.total_files == 0:
            return 0
        return min(100, int(self.scanned_files / self.total_files * 100))


ProgressCallback = Callable[[ScanProgress], None]
ResultCallback = Callable[[ResourceScanResult], None]


def _analyze_file(fivem_file: FiveMFile, resource: FiveMResource,
                  cfg: Dict) -> List[DetectionResult]:
    """Dispatch a single file to the appropriate analyzer(s)."""
    results: List[DetectionResult] = []
    ext = fivem_file.extension.lower()
    file_path = fivem_file.absolute_path

    scan_lua = cfg.get("scan", {}).get("scan_lua", True)
    scan_js = cfg.get("scan", {}).get("scan_js", True)
    scan_nui = cfg.get("scan", {}).get("scan_nui", True)
    enable_obfuscation_check = cfg.get("scan", {}).get("obfuscation_enabled", True)

    try:
        if fivem_file.is_manifest:
            results.extend(
                analyze_manifest(file_path, resource.path, resource.name)
            )

        if ext == ".lua" and not fivem_file.is_manifest:
            if not scan_lua:
                return results
            results.extend(
                analyze_lua_file(file_path, resource.name)
            )
            if enable_obfuscation_check:
                results.extend(
                    analyze_obfuscation(file_path, resource.name)
                )

        elif ext in {".js", ".mjs"}:
            if not scan_js:
                return results
            results.extend(
                analyze_js_file(file_path, resource.name)
            )
            if enable_obfuscation_check:
                results.extend(
                    analyze_obfuscation(file_path, resource.name)
                )

        elif ext in {".html", ".htm"}:
            if not scan_nui:
                return results
            # Analyze HTML for embedded JS
            results.extend(
                analyze_js_file(file_path, resource.name)
            )

        # ── Whitelisted Domain Severity Suppression ──
        whitelisted_domains = cfg.get("scan", {}).get("whitelisted_domains", [])
        for det in results:
            # Extract URLs
            urls = re.findall(r"https?://([a-zA-Z0-9.\-_]+)", det.code_context + " " + det.matched_pattern)
            for domain in urls:
                domain_lower = domain.lower()
                # Check if domain matches any whitelisted domain (exact or subdomain match)
                is_whitelisted = any(
                    domain_lower == w.lower() or domain_lower.endswith("." + w.lower())
                    for w in whitelisted_domains
                )
                if is_whitelisted:
                    # Do not lower if dynamic execution (loadstring/eval) is present
                    has_execution = any(kw in det.code_context for kw in ["loadstring", "eval", "assert", "load("])
                    if not has_execution and det.severity in ["HIGH", "CRITICAL"]:
                        det.severity = "LOW"
                        det.description += " (Legitimate domain whitelisted)"

    except Exception as e:
        pass  # Never crash the scanner on a single file

    return results


def _scan_resource(resource: FiveMResource, scan_id: int, cfg: Dict,
                   quick: bool = False,
                   progress: Optional[ScanProgress] = None) -> ResourceScanResult:
    """Scan a single FiveM resource and return the result."""
    result = ResourceScanResult(
        resource_name=resource.name,
        resource_path=resource.path,
        framework=resource.framework,
    )

    # Determine which files to scan
    if quick:
        quick_names = cfg.get("scan", {}).get("quick_scan_files", [])
        files_to_scan = get_quick_scan_files(resource, quick_names)
    else:
        files_to_scan = resource.code_files

    # Ensure manifest is always analyzed
    if resource.manifest_file and resource.manifest_file not in files_to_scan:
        files_to_scan = [resource.manifest_file] + files_to_scan

    result.total_files_scanned = len(files_to_scan)

    # Upsert resource in database
    resource_id = db.upsert_resource(resource.name, resource.path, resource.framework)

    # Check for file changes if change detection enabled
    if cfg.get("scan", {}).get("enable_change_detection", True):
        stored_hashes: Dict[str, str] = {}
        db_files = db.get_files_for_resource(resource_id)
        for f in db_files:
            stored_hashes[f["relative_path"]] = f["sha256"] or ""

        changes = detect_changes(resource.name, resource.path, stored_hashes)
        for change in changes:
            result.changed_files.append(
                f"{change.change_type.upper()}: {change.relative_path}"
            )

    all_detections: List[DetectionResult] = []

    for fivem_file in files_to_scan:
        if progress and progress.is_cancelled:
            break

        if progress:
            progress.update(
                current_file=fivem_file.filename,
                scanned_files=progress.scanned_files + 1,
            )

        # Compute hash and store file info
        file_hash = compute_sha256(fivem_file.absolute_path) or ""
        db.upsert_file(
            resource_id=resource_id,
            resource_name=resource.name,
            relative_path=fivem_file.relative_path,
            absolute_path=fivem_file.absolute_path,
            file_type=fivem_file.file_type,
            sha256=file_hash,
            size_bytes=fivem_file.size_bytes,
        )

        file_detections = _analyze_file(fivem_file, resource, cfg)
        filtered_file_detections = []
        for det in file_detections:
            line_content = ""
            if det.code_context:
                for line in det.code_context.splitlines():
                    if ">>>" in line:
                        line_content = line.replace(">>>", "").strip()
                        break
            if not line_content:
                line_content = det.matched_pattern
            if db.is_detection_safe(det.file_path, line_content, det.rule_id):
                continue
            filtered_file_detections.append(det)
        all_detections.extend(filtered_file_detections)

    result.detections = sort_detections_by_severity(all_detections)
    apply_risk_score(result)

    # Persist detections to database
    for det in result.detections:
        db.insert_detection(
            scan_id=scan_id,
            resource_id=resource_id,
            resource_name=resource.name,
            file_path=det.file_path,
            line_number=det.line_number,
            rule_id=det.rule_id,
            rule_name=det.rule_name,
            severity=det.severity,
            confidence=det.confidence,
            description=det.description,
            recommendation=det.recommendation,
            code_context=det.code_context,
            matched_pattern=det.matched_pattern,
        )

    # Update resource record
    db.update_resource_scan_result(
        resource_id=resource_id,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        total_files=result.total_files_scanned,
        total_detections=len(result.detections),
    )

    return result


# ─── Public scan functions ────────────────────────────────────────────────────

def run_full_scan(resources_path: str,
                  progress_cb: Optional[ProgressCallback] = None,
                  result_cb: Optional[ResultCallback] = None,
                  progress: Optional[ScanProgress] = None) -> List[ResourceScanResult]:
    """
    Full scan: recursively discover and scan all resources.
    """
    cfg = _load_config()
    db.init_database()
    db.set_setting("last_scan_directory", os.path.abspath(resources_path))
    _load_rules_into_db(cfg)

    if progress is None:
        progress = ScanProgress()

    resources = discover_resources(resources_path)
    total_files = sum(len(r.code_files) for r in resources)

    progress.update(
        total_resources=len(resources),
        total_files=max(total_files, 1),
        is_running=True,
    )

    scan_id = db.create_scan("full", resources_path)
    start_time = time.time()
    all_results: List[ResourceScanResult] = []

    counters = {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0, "detections": 0}

    for resource in resources:
        if progress.is_cancelled:
            break

        progress.update(current_resource=resource.name)
        if progress_cb:
            progress_cb(progress)

        result = _scan_resource(resource, scan_id, cfg, quick=False, progress=progress)
        all_results.append(result)

        progress.update(scanned_resources=progress.scanned_resources + 1)
        counters["critical"] += result.critical_count
        counters["high"] += result.high_count
        counters["medium"] += result.medium_count
        counters["low"] += result.low_count
        counters["files"] += result.total_files_scanned
        counters["detections"] += len(result.detections)
        progress.update(total_detections=counters["detections"])

        if result_cb:
            result_cb(result)
        if progress_cb:
            progress_cb(progress)

    duration = time.time() - start_time
    db.complete_scan(
        scan_id, len(resources), counters["files"], counters["detections"],
        counters["critical"], counters["high"], counters["medium"],
        counters["low"], duration,
    )

    progress.update(is_running=False)
    if progress_cb:
        progress_cb(progress)

    return all_results


def run_quick_scan(resources_path: str,
                   progress_cb: Optional[ProgressCallback] = None,
                   result_cb: Optional[ResultCallback] = None,
                   progress: Optional[ScanProgress] = None) -> List[ResourceScanResult]:
    """
    Quick scan: only priority files (manifests, server/client/shared/config).
    """
    cfg = _load_config()
    db.init_database()
    _load_rules_into_db(cfg)

    if progress is None:
        progress = ScanProgress()

    resources = discover_resources(resources_path)
    quick_names = cfg.get("scan", {}).get("quick_scan_files", [])

    # Estimate file count for progress
    total_est = 0
    for r in resources:
        total_est += len(get_quick_scan_files(r, quick_names))

    progress.update(
        total_resources=len(resources),
        total_files=max(total_est, 1),
        is_running=True,
    )

    scan_id = db.create_scan("quick", resources_path)
    start_time = time.time()
    all_results: List[ResourceScanResult] = []
    counters = {"critical": 0, "high": 0, "medium": 0, "low": 0, "files": 0, "detections": 0}

    for resource in resources:
        if progress.is_cancelled:
            break

        progress.update(current_resource=resource.name)
        if progress_cb:
            progress_cb(progress)

        result = _scan_resource(resource, scan_id, cfg, quick=True, progress=progress)
        all_results.append(result)

        progress.update(scanned_resources=progress.scanned_resources + 1)
        counters["critical"] += result.critical_count
        counters["high"] += result.high_count
        counters["medium"] += result.medium_count
        counters["low"] += result.low_count
        counters["files"] += result.total_files_scanned
        counters["detections"] += len(result.detections)
        progress.update(total_detections=counters["detections"])

        if result_cb:
            result_cb(result)
        if progress_cb:
            progress_cb(progress)

    duration = time.time() - start_time
    db.complete_scan(
        scan_id, len(resources), counters["files"], counters["detections"],
        counters["critical"], counters["high"], counters["medium"],
        counters["low"], duration,
    )

    progress.update(is_running=False)
    if progress_cb:
        progress_cb(progress)

    return all_results


def run_resource_scan(resource_path: str,
                      progress_cb: Optional[ProgressCallback] = None,
                      result_cb: Optional[ResultCallback] = None,
                      progress: Optional[ScanProgress] = None) -> Optional[ResourceScanResult]:
    """
    Scan a single specific FiveM resource directory.
    """
    cfg = _load_config()
    db.init_database()
    db.set_setting("last_scan_directory", os.path.abspath(resource_path))
    _load_rules_into_db(cfg)

    if progress is None:
        progress = ScanProgress()

    resource = discover_single_resource(resource_path)
    if not resource:
        return None

    progress.update(
        total_resources=1,
        total_files=max(len(resource.code_files), 1),
        is_running=True,
        current_resource=resource.name,
    )

    if progress_cb:
        progress_cb(progress)

    scan_id = db.create_scan("resource", resource_path)
    start_time = time.time()

    result = _scan_resource(resource, scan_id, cfg, quick=False, progress=progress)

    duration = time.time() - start_time
    db.complete_scan(
        scan_id, 1, result.total_files_scanned, len(result.detections),
        result.critical_count, result.high_count, result.medium_count,
        result.low_count, duration,
    )

    progress.update(is_running=False, scanned_resources=1)
    if result_cb:
        result_cb(result)
    if progress_cb:
        progress_cb(progress)

    return result


def run_folder_scan(folder_path: str,
                    progress_cb: Optional[ProgressCallback] = None,
                    result_cb: Optional[ResultCallback] = None,
                    progress: Optional[ScanProgress] = None) -> List[ResourceScanResult]:
    """
    Scan a custom folder path (treated as if it were a resources/ directory).
    """
    return run_full_scan(folder_path, progress_cb, result_cb, progress)


def _load_rules_into_db(cfg: Dict) -> None:
    """Load signature JSON files into the rules database table."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sig_dir = os.path.join(base, "signatures")

    sig_files = [
        "fivem_backdoors.json",
        "fivem_suspicious.json",
        "lua_obfuscation.json",
        "javascript_suspicious.json",
        "fxmanifest_rules.json",
    ]

    for sig_file in sig_files:
        sig_path = os.path.join(sig_dir, sig_file)
        if not os.path.exists(sig_path):
            continue
        try:
            with open(sig_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for rule in data.get("rules", []):
                rule["source_file"] = sig_file
                db.upsert_rule(rule)
        except Exception:
            pass
