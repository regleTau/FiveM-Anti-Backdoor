"""
core/backup_manager.py
Backup and restore system for FiveM resources before safe cleaning.
"""

import os
import shutil
import json
from datetime import datetime
from typing import Optional, List, Dict


def _get_backup_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(base, "config.json")
    backup_dir = "backups"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            backup_dir = cfg.get("backup", {}).get("directory", backup_dir)
        except Exception:
            pass
    path = os.path.join(base, backup_dir)
    os.makedirs(path, exist_ok=True)
    return path


def backup_file(file_path: str, resource_name: str, reason: str = "") -> Optional[str]:
    """
    Create a timestamped backup of a file before modification.

    Returns the backup file path on success, None on failure.
    """
    backup_dir = _get_backup_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(file_path)
    resource_backup_dir = os.path.join(backup_dir, resource_name, timestamp)
    os.makedirs(resource_backup_dir, exist_ok=True)

    backup_path = os.path.join(resource_backup_dir, filename)
    try:
        shutil.copy2(file_path, backup_path)

        # Store metadata
        meta = {
            "original_path": file_path,
            "resource_name": resource_name,
            "filename": filename,
            "backup_path": backup_path,
            "reason": reason,
            "timestamp": timestamp,
            "backed_up_at": datetime.now().isoformat(),
        }
        meta_path = os.path.join(resource_backup_dir, f"{filename}.meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return backup_path
    except Exception as e:
        return None


def backup_resource(resource_path: str, resource_name: str, reason: str = "") -> Optional[str]:
    """
    Create a full backup of an entire FiveM resource directory.

    Returns the backup directory path on success, None on failure.
    """
    backup_dir = _get_backup_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    resource_backup_dir = os.path.join(backup_dir, resource_name, timestamp + "_full")

    try:
        shutil.copytree(resource_path, resource_backup_dir)

        meta = {
            "original_path": resource_path,
            "resource_name": resource_name,
            "backup_path": resource_backup_dir,
            "reason": reason,
            "timestamp": timestamp,
            "backed_up_at": datetime.now().isoformat(),
        }
        meta_path = os.path.join(resource_backup_dir, "_backup_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return resource_backup_dir
    except Exception:
        return None


def validate_restore_destination(dest_path: str) -> bool:
    """
    Validate that the restore destination is safe and resides within the allowed workspace.
    Rejects traversals, system/UNC/network paths, and symlink/junction escapes.
    """
    try:
        from core import database as db
        allowed_root = db.get_setting("safe_workspace_root", "")
    except Exception:
        allowed_root = ""

    if not allowed_root:
        # Fallback to parent directory of project (i.e. New folder containing FiveM-Anti-Backdoor)
        allowed_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Resolve absolute canonical paths
    dest_abs = os.path.abspath(os.path.realpath(dest_path))
    root_abs = os.path.abspath(os.path.realpath(allowed_root))

    # Reject if outside allowed root
    if not dest_abs.startswith(root_abs):
        return False

    # Block traversal indicators
    if ".." in dest_path or "../" in dest_path or "..\\" in dest_path:
        return False

    # Block Windows system paths
    lower_dest = dest_abs.lower()
    system_prefixes = [
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\programdata",
    ]
    for pref in system_prefixes:
        if lower_dest.startswith(pref):
            return False

    # Block network / UNC paths
    if dest_path.startswith(("\\\\", "//")):
        return False

    return True


def restore_file(backup_path: str, original_path: str) -> bool:
    """Restore a file from backup to its original location."""
    if not validate_restore_destination(original_path):
        # Security event log
        print(f"[SECURITY] Aborted unsafe file restore traversal attempt to: {original_path}")
        return False
    try:
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.copy2(backup_path, original_path)
        return True
    except Exception:
        return False


def list_backups(resource_name: Optional[str] = None) -> List[Dict]:
    """List all available backups, optionally filtered by resource name."""
    backup_dir = _get_backup_dir()
    results = []

    if resource_name:
        search_root = os.path.join(backup_dir, resource_name)
        if not os.path.isdir(search_root):
            return []
        resource_dirs = [resource_name]
    else:
        try:
            resource_dirs = os.listdir(backup_dir)
        except OSError:
            return []

    for rname in resource_dirs:
        rpath = os.path.join(backup_dir, rname)
        if not os.path.isdir(rpath):
            continue
        try:
            timestamps = os.listdir(rpath)
        except OSError:
            continue

        for ts in timestamps:
            ts_path = os.path.join(rpath, ts)
            if not os.path.isdir(ts_path):
                continue
            meta_files = [f for f in os.listdir(ts_path) if f.endswith(".meta.json")]
            for mf in meta_files:
                try:
                    with open(os.path.join(ts_path, mf), "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    results.append(meta)
                except Exception:
                    pass
    results.sort(key=lambda x: x.get("backed_up_at", ""), reverse=True)
    return results


def delete_backup(backup_path: str) -> bool:
    """Delete a backup file or directory."""
    try:
        if os.path.isfile(backup_path):
            os.remove(backup_path)
            # Also remove meta
            meta_path = backup_path + ".meta.json"
            if os.path.exists(meta_path):
                os.remove(meta_path)
        elif os.path.isdir(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)
        return True
    except Exception:
        return False
