"""
core/change_detector.py
SHA-256-based file change detection for FiveM resources.
"""

import hashlib
import os
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class FileChange:
    relative_path: str
    absolute_path: str
    resource_name: str
    previous_hash: Optional[str]
    current_hash: str
    change_type: str   # "new" | "modified" | "deleted"


def compute_sha256(file_path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return None


def compute_content_sha256(content: str) -> str:
    """Compute SHA-256 of a string content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def detect_changes(resource_name: str, resource_path: str,
                   stored_hashes: Dict[str, str]) -> List[FileChange]:
    """
    Compare current file hashes against stored hashes for a resource.

    Args:
        resource_name: Name of the FiveM resource
        resource_path: Absolute path to the resource directory
        stored_hashes: Dict of {relative_path: sha256} from the database

    Returns:
        List of FileChange objects for any modified/new/deleted files
    """
    changes: List[FileChange] = []
    current_files: Dict[str, str] = {}

    # Walk the directory and compute current hashes
    skip_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".mp3", ".mp4", ".ogg", ".wav", ".webm",
        ".dds", ".ytd", ".ydr", ".yft", ".ybn",
        ".zip", ".rar", ".7z",
    }

    for root, dirs, filenames in os.walk(resource_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in skip_exts:
                continue
            abs_path = os.path.join(root, filename)
            rel_path = os.path.normpath(os.path.relpath(abs_path, resource_path))
            current_hash = compute_sha256(abs_path)
            if current_hash:
                current_files[rel_path] = current_hash

    # Check for new or modified files
    for rel_path, current_hash in current_files.items():
        prev_hash = stored_hashes.get(rel_path)
        if prev_hash is None:
            changes.append(FileChange(
                relative_path=rel_path,
                absolute_path=os.path.join(resource_path, rel_path),
                resource_name=resource_name,
                previous_hash=None,
                current_hash=current_hash,
                change_type="new",
            ))
        elif prev_hash != current_hash:
            changes.append(FileChange(
                relative_path=rel_path,
                absolute_path=os.path.join(resource_path, rel_path),
                resource_name=resource_name,
                previous_hash=prev_hash,
                current_hash=current_hash,
                change_type="modified",
            ))

    # Check for deleted files
    for rel_path, prev_hash in stored_hashes.items():
        if rel_path not in current_files:
            changes.append(FileChange(
                relative_path=rel_path,
                absolute_path=os.path.join(resource_path, rel_path),
                resource_name=resource_name,
                previous_hash=prev_hash,
                current_hash="",
                change_type="deleted",
            ))

    return changes


def get_resource_file_hashes(resource_path: str) -> Dict[str, str]:
    """Walk a resource directory and return a dict of {relative_path: sha256}."""
    hashes: Dict[str, str] = {}
    skip_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".mp3", ".mp4", ".ogg", ".wav", ".webm",
        ".dds", ".ytd", ".ydr", ".yft", ".ybn",
        ".zip", ".rar", ".7z",
    }
    for root, dirs, filenames in os.walk(resource_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in skip_exts:
                continue
            abs_path = os.path.join(root, filename)
            rel_path = os.path.normpath(os.path.relpath(abs_path, resource_path))
            h = compute_sha256(abs_path)
            if h:
                hashes[rel_path] = h
    return hashes
