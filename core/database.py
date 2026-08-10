"""
core/database.py
SQLite database layer for FiveM Anti-Backdoor.
Handles: resources, files, detections, scans, quarantine, rules, settings tables.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any


def _get_db_path() -> str:
    """Resolve database path relative to the application root."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(base, "config.json")
    db_name = "fivem_security.db"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            db_name = cfg.get("database", {}).get("path", db_name)
        except Exception:
            pass
    return os.path.join(base, db_name)


DB_PATH = _get_db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    framework TEXT DEFAULT 'unknown',
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'SAFE',
    last_scan TEXT,
    total_files INTEGER DEFAULT 0,
    total_detections INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    resource_name TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    absolute_path TEXT NOT NULL,
    file_type TEXT,
    sha256 TEXT,
    size_bytes INTEGER DEFAULT 0,
    last_seen TEXT,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    resource_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    description TEXT,
    recommendation TEXT,
    code_context TEXT,
    matched_pattern TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target_path TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    total_resources INTEGER DEFAULT 0,
    total_files INTEGER DEFAULT 0,
    total_detections INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    filename TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT,
    detection_reason TEXT,
    rule_id TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT,
    status TEXT DEFAULT 'quarantined',
    quarantined_at TEXT NOT NULL,
    restored_at TEXT,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    description TEXT,
    recommendation TEXT,
    pattern_type TEXT,
    patterns TEXT,
    file_types TEXT,
    enabled INTEGER DEFAULT 1,
    source_file TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS safe_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    line_content TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(file_path, line_content, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_detections_scan ON detections(scan_id);
CREATE INDEX IF NOT EXISTS idx_detections_resource ON detections(resource_name);
CREATE INDEX IF NOT EXISTS idx_files_resource ON files(resource_id);
CREATE INDEX IF NOT EXISTS idx_resources_name ON resources(name);
"""


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_database() -> None:
    """Initialize the database schema."""
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Resource operations
# ---------------------------------------------------------------------------

def upsert_resource(name: str, path: str, framework: str = "unknown") -> int:
    """Insert or update a resource record. Returns the resource id."""
    now = datetime.now().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM resources WHERE path = ?", (path,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE resources SET name=?, framework=?, updated_at=? WHERE id=?",
            (name, framework, now, row["id"]),
        )
        rid = row["id"]
    else:
        cur.execute(
            "INSERT INTO resources (name, path, framework, created_at, updated_at) VALUES (?,?,?,?,?)",
            (name, path, framework, now, now),
        )
        rid = cur.lastrowid
    conn.commit()
    conn.close()
    return rid


def update_resource_scan_result(resource_id: int, risk_score: int, risk_level: str,
                                total_files: int, total_detections: int) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute(
        """UPDATE resources SET risk_score=?, risk_level=?, last_scan=?,
           total_files=?, total_detections=?, updated_at=? WHERE id=?""",
        (risk_score, risk_level, now, total_files, total_detections, now, resource_id),
    )
    conn.commit()
    conn.close()


def get_all_resources() -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM resources ORDER BY risk_score DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_resource_by_id(resource_id: int) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_resource(resource_id: int) -> None:
    conn = get_connection()
    conn.execute("DELETE FROM resources WHERE id=?", (resource_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

def upsert_file(resource_id: int, resource_name: str, relative_path: str,
                absolute_path: str, file_type: str, sha256: str, size_bytes: int) -> int:
    now = datetime.now().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM files WHERE resource_id=? AND relative_path=?",
        (resource_id, relative_path),
    )
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE files SET sha256=?, size_bytes=?, last_seen=? WHERE id=?",
            (sha256, size_bytes, now, row["id"]),
        )
        fid = row["id"]
    else:
        cur.execute(
            """INSERT INTO files (resource_id, resource_name, relative_path,
               absolute_path, file_type, sha256, size_bytes, last_seen)
               VALUES (?,?,?,?,?,?,?,?)""",
            (resource_id, resource_name, relative_path, absolute_path,
             file_type, sha256, size_bytes, now),
        )
        fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid


def get_file_hash(resource_id: int, relative_path: str) -> Optional[str]:
    conn = get_connection()
    row = conn.execute(
        "SELECT sha256 FROM files WHERE resource_id=? AND relative_path=?",
        (resource_id, relative_path),
    ).fetchone()
    conn.close()
    return row["sha256"] if row else None


def get_files_for_resource(resource_id: int) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM files WHERE resource_id=? ORDER BY relative_path", (resource_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scan operations
# ---------------------------------------------------------------------------

def create_scan(scan_type: str, target_path: str) -> int:
    now = datetime.now().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (scan_type, target_path, status, started_at) VALUES (?,?,?,?)",
        (scan_type, target_path, "running", now),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid


def complete_scan(scan_id: int, total_resources: int, total_files: int,
                  total_detections: int, critical: int, high: int,
                  medium: int, low: int, duration: float) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute(
        """UPDATE scans SET status='completed', total_resources=?, total_files=?,
           total_detections=?, critical_count=?, high_count=?, medium_count=?,
           low_count=?, duration_seconds=?, completed_at=? WHERE id=?""",
        (total_resources, total_files, total_detections, critical, high,
         medium, low, duration, now, scan_id),
    )
    conn.commit()
    conn.close()


def fail_scan(scan_id: int, error: str) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status='failed', completed_at=? WHERE id=?",
        (now, scan_id),
    )
    conn.commit()
    conn.close()


def get_recent_scans(limit: int = 20) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Detection operations
# ---------------------------------------------------------------------------

def insert_detection(scan_id: int, resource_id: int, resource_name: str,
                     file_path: str, line_number: Optional[int], rule_id: str,
                     rule_name: str, severity: str, confidence: int,
                     description: str, recommendation: str,
                     code_context: str, matched_pattern: str) -> int:
    now = datetime.now().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO detections (scan_id, resource_id, resource_name, file_path,
           line_number, rule_id, rule_name, severity, confidence, description,
           recommendation, code_context, matched_pattern, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, resource_id, resource_name, file_path, line_number,
         rule_id, rule_name, severity, confidence, description,
         recommendation, code_context, matched_pattern, now),
    )
    did = cur.lastrowid
    conn.commit()
    conn.close()
    return did


def get_detections_for_scan(scan_id: int) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM detections WHERE scan_id=? ORDER BY severity, resource_name, file_path",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_detections_for_resource(resource_name: str) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT d.* FROM detections d
           JOIN scans s ON d.scan_id = s.id
           WHERE d.resource_name=? AND s.status='completed'
           ORDER BY d.created_at DESC""",
        (resource_name,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_detections(limit: int = 500) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT d.* FROM detections d
           JOIN scans s ON d.scan_id = s.id
           WHERE s.status='completed'
           ORDER BY d.created_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_detection_summary() -> Dict[str, int]:
    conn = get_connection()
    row = conn.execute(
        """SELECT
             COUNT(*) as total,
             SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
             SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium,
             SUM(CASE WHEN severity='LOW' THEN 1 ELSE 0 END) as low
           FROM detections d
           JOIN scans s ON d.scan_id = s.id
           WHERE s.status='completed'"""
    ).fetchone()
    conn.close()
    if row:
        return {
            "total": row["total"] or 0,
            "critical": row["critical"] or 0,
            "high": row["high"] or 0,
            "medium": row["medium"] or 0,
            "low": row["low"] or 0,
        }
    return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


# ---------------------------------------------------------------------------
# Quarantine operations
# ---------------------------------------------------------------------------

def insert_quarantine(original_path: str, resource_name: str, filename: str,
                      quarantine_path: str, sha256: str, detection_reason: str,
                      rule_id: str, risk_score: int, risk_level: str) -> int:
    now = datetime.now().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO quarantine (original_path, resource_name, filename,
           quarantine_path, sha256, detection_reason, rule_id, risk_score,
           risk_level, status, quarantined_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (original_path, resource_name, filename, quarantine_path, sha256,
         detection_reason, rule_id, risk_score, risk_level, "quarantined", now),
    )
    qid = cur.lastrowid
    conn.commit()
    conn.close()
    return qid


def get_quarantine_items() -> List[Dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM quarantine WHERE status='quarantined' ORDER BY quarantined_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_quarantine_status(qid: int, status: str) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    if status == "restored":
        conn.execute(
            "UPDATE quarantine SET status=?, restored_at=? WHERE id=?",
            (status, now, qid),
        )
    elif status == "deleted":
        conn.execute(
            "UPDATE quarantine SET status=?, deleted_at=? WHERE id=?",
            (status, now, qid),
        )
    else:
        conn.execute("UPDATE quarantine SET status=? WHERE id=?", (status, qid))
    conn.commit()
    conn.close()


def get_quarantine_by_id(qid: int) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Rules operations
# ---------------------------------------------------------------------------

def upsert_rule(rule_data: Dict) -> None:
    now = datetime.now().isoformat()
    patterns = json.dumps(rule_data.get("patterns", []))
    file_types = json.dumps(rule_data.get("file_types", []))
    conn = get_connection()
    conn.execute(
        """INSERT INTO rules (rule_id, name, severity, confidence, description,
           recommendation, pattern_type, patterns, file_types, enabled, source_file,
           created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(rule_id) DO UPDATE SET
           name=excluded.name, severity=excluded.severity,
           confidence=excluded.confidence, description=excluded.description,
           recommendation=excluded.recommendation, pattern_type=excluded.pattern_type,
           patterns=excluded.patterns, file_types=excluded.file_types,
           source_file=excluded.source_file, updated_at=excluded.updated_at""",
        (
            rule_data.get("id", rule_data.get("rule_id", "")),
            rule_data.get("name", ""),
            rule_data.get("severity", "LOW"),
            rule_data.get("confidence", 50),
            rule_data.get("description", ""),
            rule_data.get("recommendation", ""),
            rule_data.get("pattern_type", "regex"),
            patterns,
            file_types,
            1,
            rule_data.get("source_file", ""),
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()


def get_all_rules() -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM rules ORDER BY severity, rule_id").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["patterns"] = json.loads(d["patterns"])
        except Exception:
            d["patterns"] = []
        try:
            d["file_types"] = json.loads(d["file_types"])
        except Exception:
            d["file_types"] = []
        result.append(d)
    return result


def toggle_rule(rule_id: str, enabled: bool) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE rules SET enabled=? WHERE rule_id=?",
        (1 if enabled else 0, rule_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Settings operations
# ---------------------------------------------------------------------------

def get_setting(key: str, default: Any = None) -> Any:
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]
    return default


def set_setting(key: str, value: Any) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value), now),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Safe / Whitelisted detections
# ---------------------------------------------------------------------------

def mark_detection_safe(file_path: str, line_content: str, rule_id: str) -> None:
    now = datetime.now().isoformat()
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO safe_detections (file_path, line_content, rule_id, created_at) VALUES (?,?,?,?)",
            (file_path, line_content, rule_id, now)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def is_detection_safe(file_path: str, line_content: str, rule_id: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT id FROM safe_detections WHERE file_path=? AND line_content=? AND rule_id=?",
        (file_path, line_content, rule_id)
    ).fetchone()
    conn.close()
    return row is not None


def delete_detection(detection_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM detections WHERE id=?", (detection_id,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def clear_active_scan_data() -> None:
    """Deletes active/current scan records from resources, files, and detections tables."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM detections")
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM resources")
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


