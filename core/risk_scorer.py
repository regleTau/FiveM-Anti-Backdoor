"""
core/risk_scorer.py
Risk scoring engine for FiveM resources.
Combines detection severity, confidence, and count into a 0-100 risk score.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

RISK_LEVELS = [
    (81, 100, "CRITICAL"),
    (61, 80,  "HIGH"),
    (41, 60,  "MEDIUM"),
    (21, 40,  "LOW"),
    (0,  20,  "SAFE"),
]

DEFAULT_SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
}


@dataclass
class DetectionResult:
    """A single detection result from any analyzer."""
    rule_id: str
    rule_name: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    confidence: int          # 0-100
    description: str
    recommendation: str
    file_path: str           # absolute path
    line_number: Optional[int] = None
    code_context: str = ""
    matched_pattern: str = ""
    resource_name: str = ""

    @property
    def severity_upper(self) -> str:
        return self.severity.upper()

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_context": self.code_context,
            "matched_pattern": self.matched_pattern,
            "resource_name": self.resource_name,
        }


@dataclass
class ResourceScanResult:
    """Aggregated scan result for a single FiveM resource."""
    resource_name: str
    resource_path: str
    framework: str
    detections: List[DetectionResult] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "SAFE"
    total_files_scanned: int = 0
    changed_files: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.detections if d.severity_upper == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for d in self.detections if d.severity_upper == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for d in self.detections if d.severity_upper == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for d in self.detections if d.severity_upper == "LOW")

    def to_dict(self) -> Dict:
        return {
            "resource_name": self.resource_name,
            "resource_path": self.resource_path,
            "framework": self.framework,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_files_scanned": self.total_files_scanned,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "detections": [d.to_dict() for d in self.detections],
            "changed_files": self.changed_files,
        }


def score_risk(detections: List[DetectionResult],
               weights: Optional[Dict[str, int]] = None) -> int:
    """
    Calculate a 0-100 risk score from a list of detections.

    Algorithm:
    - Each detection contributes: weight * (confidence / 100)
    - Scores are capped at 100
    - Multiple detections of the same severity compound but with diminishing returns
    """
    if not detections:
        return 0

    if weights is None:
        weights = DEFAULT_SEVERITY_WEIGHTS

    score = 0.0
    severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for det in detections:
        sev = det.severity_upper
        w = weights.get(sev, 5)
        conf_factor = det.confidence / 100.0
        # Diminishing returns for same severity
        count = severity_counts.get(sev, 0)
        diminish = 1.0 / (1.0 + count * 0.2)
        score += w * conf_factor * diminish
        severity_counts[sev] = count + 1

    return min(100, int(round(score)))


def get_risk_level(score: int) -> str:
    """Map a numeric score to a risk level string."""
    for lo, hi, level in RISK_LEVELS:
        if lo <= score <= hi:
            return level
    return "SAFE"


def apply_risk_score(result: ResourceScanResult,
                     weights: Optional[Dict[str, int]] = None) -> ResourceScanResult:
    """Compute and assign risk_score and risk_level to a ResourceScanResult."""
    result.risk_score = score_risk(result.detections, weights)
    result.risk_level = get_risk_level(result.risk_score)
    return result


def get_severity_color(severity: str) -> str:
    """Return a CSS/hex color string for a given severity level."""
    colors = {
        "CRITICAL": "#FF4444",
        "HIGH": "#FF8C00",
        "MEDIUM": "#FFD700",
        "LOW": "#4CAF50",
        "SAFE": "#2196F3",
    }
    return colors.get(severity.upper(), "#AAAAAA")


def get_risk_level_color(level: str) -> str:
    """Return a CSS/hex color for a risk level."""
    return get_severity_color(level)


def sort_detections_by_severity(detections: List[DetectionResult]) -> List[DetectionResult]:
    """Sort detections from most to least severe."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(detections, key=lambda d: order.get(d.severity_upper, 99))
