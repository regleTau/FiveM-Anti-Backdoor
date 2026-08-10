"""
core/quarantine_manager.py
Quarantine system for suspicious FiveM resource files.
Moves files to an isolated quarantine directory and tracks them in the database.
"""

import os
import shutil
import json
from datetime import datetime
from typing import Optional, Dict

from core.change_detector import compute_sha256
from core import database as db


def _get_quarantine_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(base, "config.json")
    q_dir = "quarantine"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            q_dir = cfg.get("quarantine", {}).get("directory", q_dir)
        except Exception:
            pass
    path = os.path.join(base, q_dir)
    os.makedirs(path, exist_ok=True)
    return path


def quarantine_file(file_path: str, resource_name: str,
                    detection_reason: str, rule_id: str,
                    risk_score: int, risk_level: str,
                    copy_only: bool = False) -> Optional[Dict]:
    """
    Move (or copy) a suspicious file to the quarantine directory.

    Args:
        file_path: Absolute path to the file to quarantine
        resource_name: Name of the FiveM resource
        detection_reason: Why this file was quarantined
        rule_id: Rule ID that triggered the quarantine
        risk_score: Risk score (0-100)
        risk_level: Risk level string
        copy_only: If True, copy file instead of moving it

    Returns:
        Dict with quarantine details or None on failure
    """
    if not os.path.isfile(file_path):
        return None

    q_dir = _get_quarantine_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = os.path.basename(file_path)
    resource_q_dir = os.path.join(q_dir, resource_name)
    os.makedirs(resource_q_dir, exist_ok=True)

    # Store with timestamp to avoid name collisions
    quarantine_filename = f"{timestamp}_{filename}"
    quarantine_path = os.path.join(resource_q_dir, quarantine_filename)

    sha256 = compute_sha256(file_path) or ""

    try:
        if copy_only:
            shutil.copy2(file_path, quarantine_path)
        else:
            shutil.move(file_path, quarantine_path)
    except Exception as e:
        return None

    # Write metadata JSON alongside quarantined file
    meta = {
        "original_path": file_path,
        "resource_name": resource_name,
        "filename": filename,
        "quarantine_path": quarantine_path,
        "sha256": sha256,
        "detection_reason": detection_reason,
        "rule_id": rule_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "quarantined_at": datetime.now().isoformat(),
        "copy_only": copy_only,
    }
    meta_path = quarantine_path + ".meta.json"
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass

    # Register in database
    qid = db.insert_quarantine(
        original_path=file_path,
        resource_name=resource_name,
        filename=filename,
        quarantine_path=quarantine_path,
        sha256=sha256,
        detection_reason=detection_reason,
        rule_id=rule_id,
        risk_score=risk_score,
        risk_level=risk_level,
    )

    meta["id"] = qid
    return meta


def restore_quarantined_file(quarantine_id: int) -> bool:
    """
    Restore a quarantined file to its original location.

    Returns True on success.
    """
    item = db.get_quarantine_by_id(quarantine_id)
    if not item:
        return False

    quarantine_path = item["quarantine_path"]
    original_path = item["original_path"]

    from core.backup_manager import validate_restore_destination
    if not validate_restore_destination(original_path):
        print(f"[SECURITY] Aborted unsafe quarantine file restore traversal attempt to: {original_path}")
        return False

    if not os.path.isfile(quarantine_path):
        return False

    try:
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.copy2(quarantine_path, original_path)
        db.update_quarantine_status(quarantine_id, "restored")
        return True
    except Exception:
        return False


def delete_quarantine_item(quarantine_id: int) -> bool:
    """
    Permanently delete a quarantined file.

    Returns True on success.
    """
    item = db.get_quarantine_by_id(quarantine_id)
    if not item:
        return False

    quarantine_path = item["quarantine_path"]
    meta_path = quarantine_path + ".meta.json"

    try:
        if os.path.isfile(quarantine_path):
            os.remove(quarantine_path)
        if os.path.isfile(meta_path):
            os.remove(meta_path)
        db.update_quarantine_status(quarantine_id, "deleted")
        return True
    except Exception:
        return False


def get_quarantine_details(quarantine_id: int) -> Optional[Dict]:
    """Get detailed quarantine information including file content preview."""
    item = db.get_quarantine_by_id(quarantine_id)
    if not item:
        return None

    result = dict(item)
    quarantine_path = item["quarantine_path"]

    # Try to read a safe preview of the quarantined file
    if os.path.isfile(quarantine_path):
        try:
            with open(quarantine_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(4096)
            result["content_preview"] = content
        except Exception:
            result["content_preview"] = "[Could not read file]"
        result["file_size"] = os.path.getsize(quarantine_path)
    else:
        result["content_preview"] = "[File not found in quarantine]"
        result["file_size"] = 0

    return result
