"""
reports/json_reporter.py
Generates structured JSON security reports for FiveM scan results.
"""

import os
import json
from datetime import datetime
from typing import List, Optional

from core.risk_scorer import ResourceScanResult


def _get_reports_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(base, "config.json")
    r_dir = "scan_reports"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            r_dir = cfg.get("reports", {}).get("directory", r_dir)
        except Exception:
            pass
    path = os.path.join(base, r_dir)
    os.makedirs(path, exist_ok=True)
    return path


def generate_json_report(results: List[ResourceScanResult],
                          scan_type: str = "full",
                          target_path: str = "",
                          duration_seconds: float = 0.0,
                          output_path: Optional[str] = None) -> str:
    """
    Generate a JSON security report from scan results.
    Returns the path to the generated JSON file.
    """
    reports_dir = _get_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_path is None:
        output_path = os.path.join(reports_dir, f"scan_report_{timestamp}.json")

    total_resources = len(results)
    total_files = sum(r.total_files_scanned for r in results)
    total_detections = sum(len(r.detections) for r in results)
    critical_count = sum(r.critical_count for r in results)
    high_count = sum(r.high_count for r in results)
    medium_count = sum(r.medium_count for r in results)
    low_count = sum(r.low_count for r in results)

    report = {
        "report_meta": {
            "generator": "FiveM Anti-Backdoor v1.0.0",
            "generated_at": datetime.now().isoformat(),
            "scan_type": scan_type,
            "target_path": target_path,
            "duration_seconds": round(duration_seconds, 2),
        },
        "summary": {
            "total_resources": total_resources,
            "total_files_scanned": total_files,
            "total_detections": total_detections,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "clean_resources": sum(1 for r in results if not r.detections),
            "affected_resources": sum(1 for r in results if r.detections),
        },
        "resources": [],
    }

    for r in sorted(results, key=lambda x: x.risk_score, reverse=True):
        resource_data = {
            "name": r.resource_name,
            "path": r.resource_path,
            "framework": r.framework,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "files_scanned": r.total_files_scanned,
            "detection_count": len(r.detections),
            "critical_count": r.critical_count,
            "high_count": r.high_count,
            "medium_count": r.medium_count,
            "low_count": r.low_count,
            "changed_files": r.changed_files,
            "detections": [],
        }

        for det in r.detections:
            resource_data["detections"].append({
                "rule_id": det.rule_id,
                "rule_name": det.rule_name,
                "severity": det.severity,
                "confidence": det.confidence,
                "file": det.file_path,
                "line": det.line_number,
                "description": det.description,
                "recommendation": det.recommendation,
                "matched_pattern": det.matched_pattern,
                "code_context": det.code_context,
            })

        report["resources"].append(resource_data)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path
