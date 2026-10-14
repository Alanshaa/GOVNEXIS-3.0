"""SQLite Database Access Layer for GOVNEXIS 3.0.

Provides robust, parameterized persistence for:
- Audited scans and raw JSON snapshots
- Individual configuration findings with CVSS v3.0 metrics
- Remediation task lifecycles (Open -> In Progress -> Fixed -> Verified)
- Executive analytics and trend computations
- Safe schema initialization and backward-compatible migrations
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, List, Any, Optional

from config import (
    DATABASE_PATH, STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)


def get_db_path(custom_path: Optional[str] = None) -> str:
    """Resolve active database path, with fallback to config DATABASE_PATH."""
    if custom_path:
        return custom_path
    try:
        from flask import current_app
        if current_app and current_app.config.get("DATABASE_PATH"):
            return current_app.config["DATABASE_PATH"]
    except Exception:
        pass
    return os.environ.get("DATABASE_PATH", DATABASE_PATH)


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create and return a database connection with row factory enabled."""
    resolved_path = get_db_path(db_path)
    # Ensure parent directory exists if using a subfolder
    if resolved_path != ":memory:" and not os.path.isabs(resolved_path):
        resolved_path = os.path.abspath(resolved_path)
    if resolved_path != ":memory:":
        parent = os.path.dirname(resolved_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(resolved_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None):
    """Initialize database tables, indexes, and apply safe migrations."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                letter_grade TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0,
                total_checks INTEGER NOT NULL,
                passed_checks INTEGER NOT NULL,
                failed_checks INTEGER NOT NULL,
                warning_checks INTEGER NOT NULL,
                not_assessed_checks INTEGER NOT NULL,
                critical_high_count INTEGER NOT NULL,
                max_cvss_score REAL DEFAULT 0.0,
                max_cvss_severity TEXT DEFAULT 'None',
                raw_json TEXT NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                check_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL,
                why_it_matters TEXT NOT NULL,
                potential_impact TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                verification_status TEXT NOT NULL DEFAULT 'Open',
                cvss_score REAL DEFAULT NULL,
                cvss_severity TEXT DEFAULT 'Not Scored',
                cvss_vector TEXT DEFAULT NULL,
                cvss_status TEXT DEFAULT 'Not Scored',
                cvss_unscored_reason TEXT DEFAULT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_host TEXT NOT NULL,
                check_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                notes TEXT DEFAULT '',
                updated_at TEXT NOT NULL
            );
        """)

        # Backward-compatible migrations for scans table
        cursor.execute("PRAGMA table_info(scans)")
        existing_scan_cols = [row["name"] for row in cursor.fetchall()]
        if "max_cvss_score" not in existing_scan_cols:
            cursor.execute("ALTER TABLE scans ADD COLUMN max_cvss_score REAL DEFAULT 0.0")
        if "max_cvss_severity" not in existing_scan_cols:
            cursor.execute("ALTER TABLE scans ADD COLUMN max_cvss_severity TEXT DEFAULT 'None'")

        # Backward-compatible migrations for findings table
        cursor.execute("PRAGMA table_info(findings)")
        existing_cols = [row["name"] for row in cursor.fetchall()]
        if "cvss_score" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT NULL")
        if "cvss_severity" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN cvss_severity TEXT DEFAULT 'Not Scored'")
        if "cvss_vector" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN cvss_vector TEXT DEFAULT NULL")
        if "cvss_status" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN cvss_status TEXT DEFAULT 'Not Scored'")
        if "cvss_unscored_reason" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN cvss_unscored_reason TEXT DEFAULT NULL")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_target ON remediation_tasks(target_host);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_tasks(status);")
        conn.commit()


def save_scan(scan_result: Any, db_path: Optional[str] = None) -> int:
    """Persist a completed scan result and its individual findings into SQLite."""
    init_db(db_path)

    total_checks = len(scan_result.findings)
    passed_checks = sum(1 for f in scan_result.findings if f.status == STATUS_PASS)
    failed_checks = sum(1 for f in scan_result.findings if f.status == STATUS_FAIL)
    warning_checks = sum(1 for f in scan_result.findings if f.status == STATUS_WARNING)
    not_assessed_checks = sum(1 for f in scan_result.findings if f.status == STATUS_NOT_ASSESSED)
    critical_high_count = scan_result.score_report.critical_high_count

    max_cvss = getattr(scan_result.score_report, "max_cvss_score", 0.0) or 0.0
    if max_cvss >= 9.0:
        max_sev = "Critical"
    elif max_cvss >= 7.0:
        max_sev = "High"
    elif max_cvss >= 4.0:
        max_sev = "Medium"
    elif max_cvss > 0.0:
        max_sev = "Low"
    else:
        max_sev = "None"

    raw_json = json.dumps(scan_result.to_dict())

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                target_url, final_url, hostname, timestamp, score, letter_grade,
                status_code, duration_ms, is_demo, total_checks, passed_checks,
                failed_checks, warning_checks, not_assessed_checks,
                critical_high_count, max_cvss_score, max_cvss_severity, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_result.target_url,
            scan_result.final_url,
            scan_result.hostname,
            scan_result.timestamp,
            scan_result.score_report.final_score,
            scan_result.score_report.letter_grade,
            scan_result.status_code,
            scan_result.duration_ms,
            1 if scan_result.is_demo else 0,
            total_checks,
            passed_checks,
            failed_checks,
            warning_checks,
            not_assessed_checks,
            critical_high_count,
            max_cvss,
            max_sev,
            raw_json
        ))
        scan_id = cursor.lastrowid

        from core.cvss import assign_finding_cvss

        for finding in scan_result.findings:
            cvss_data = getattr(finding, "cvss", None)
            if not cvss_data:
                cvss_data = assign_finding_cvss(finding.check_id, finding.status, finding.evidence, finding.severity)

            cursor.execute("""
                INSERT INTO findings (
                    scan_id, check_id, title, category, severity, status,
                    evidence, why_it_matters, potential_impact, recommended_action,
                    verification_status, cvss_score, cvss_severity, cvss_vector,
                    cvss_status, cvss_unscored_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding.check_id,
                finding.title,
                finding.category,
                finding.severity,
                finding.status,
                finding.evidence,
                finding.why_it_matters,
                finding.potential_impact,
                finding.recommended_action,
                "Open" if finding.status in (STATUS_FAIL, STATUS_WARNING) else "Verified",
                cvss_data.base_score,
                cvss_data.severity,
                cvss_data.vector_string,
                cvss_data.status,
                cvss_data.unscored_reason,
            ))

            # Maintain or insert remediation task if issue exists
            if finding.status in (STATUS_FAIL, STATUS_WARNING):
                cursor.execute("""
                    SELECT id FROM remediation_tasks
                    WHERE target_host = ? AND check_id = ?
                """, (scan_result.hostname, finding.check_id))
                row = cursor.fetchone()
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                if not row:
                    cursor.execute("""
                        INSERT INTO remediation_tasks (target_host, check_id, title, status, notes, updated_at)
                        VALUES (?, ?, ?, 'Open', '', ?)
                    """, (scan_result.hostname, finding.check_id, finding.title, now))

        conn.commit()
        return scan_id


def get_scan(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full scan details and associated findings by scan_id."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        scan_data = dict(row)
        scan_data["details"] = json.loads(scan_data["raw_json"])

        cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
        scan_data["findings"] = [dict(f) for f in cursor.fetchall()]

        max_c = scan_data.get("max_cvss_score")
        if max_c is None or max_c == 0.0:
            scored_vals = [f["cvss_score"] for f in scan_data["findings"] if f.get("cvss_score") is not None and f.get("cvss_status") == "SCORED"]
            max_c = max(scored_vals) if scored_vals else 0.0
        scan_data["max_cvss"] = float(max_c)
        scan_data["cvss_severity"] = (
            "Critical" if max_c >= 9.0 else
            "High" if max_c >= 7.0 else
            "Medium" if max_c >= 4.0 else
            "Low" if max_c > 0.0 else "None"
        )
        return scan_data


def get_all_scans(limit: int = 100, offset: int = 0, hostname_filter: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve list of scans ordered by most recent first, with CVSS v3.0 metrics."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        if hostname_filter:
            cursor.execute(
                "SELECT * FROM scans WHERE hostname LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (f"%{hostname_filter}%", limit, offset)
            )
        else:
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
        scans = [dict(r) for r in cursor.fetchall()]

        for s in scans:
            max_c = s.get("max_cvss_score")
            if max_c is None or max_c == 0.0:
                try:
                    raw_data = json.loads(s.get("raw_json") or "{}")
                    max_c = raw_data.get("score_report", {}).get("max_cvss_score", 0.0)
                except Exception:
                    max_c = 0.0

            if max_c is None or max_c == 0.0:
                cursor.execute(
                    "SELECT MAX(cvss_score) FROM findings WHERE scan_id = ? AND cvss_status = 'SCORED' AND cvss_score IS NOT NULL",
                    (s["id"],)
                )
                db_max = cursor.fetchone()[0]
                if db_max is not None:
                    max_c = float(db_max)

            max_c = float(max_c or 0.0)
            s["max_cvss"] = max_c
            s["cvss_severity"] = (
                "Critical" if max_c >= 9.0 else
                "High" if max_c >= 7.0 else
                "Medium" if max_c >= 4.0 else
                "Low" if max_c > 0.0 else "None"
            )

        return scans


def get_scans_count(hostname_filter: Optional[str] = None, db_path: Optional[str] = None) -> int:
    """Return total number of saved scans."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        if hostname_filter:
            cursor.execute("SELECT COUNT(*) FROM scans WHERE hostname LIKE ?", (f"%{hostname_filter}%",))
        else:
            cursor.execute("SELECT COUNT(*) FROM scans")
        return cursor.fetchone()[0] or 0


def delete_scan(scan_id: int, db_path: Optional[str] = None) -> bool:
    """Delete a scan and its associated findings."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def delete_all_scans(db_path: Optional[str] = None):
    """Clear all scans, findings, and remediation tasks from database."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings")
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM remediation_tasks")
        conn.commit()


def get_scan_trends(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculate executive dashboard metrics across all historical scans with CVSS distribution."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*), COUNT(DISTINCT hostname), AVG(score) FROM scans")
        scans_count_row = cursor.fetchone()
        total_scans = scans_count_row[0] or 0
        unique_targets = scans_count_row[1] or 0
        avg_score = round(scans_count_row[2] or 0.0, 1)

        # Latest scan info
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1")
        latest_row = cursor.fetchone()
        latest_scan = dict(latest_row) if latest_row else None

        # Configuration severity counts
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM findings
            WHERE status IN ('FAIL', 'WARNING')
            GROUP BY severity
        """)
        severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}
        for s in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO):
            severity_counts.setdefault(s, 0)

        # Official CVSS v3.0 Severity Distribution across active findings
        cursor.execute("""
            SELECT 
                COALESCE(cvss_severity, 'Not Scored') as sev,
                COUNT(*) as count
            FROM findings
            WHERE status IN ('FAIL', 'WARNING')
            GROUP BY sev
        """)
        cvss_severity_counts = {row["sev"]: row["count"] for row in cursor.fetchall()}
        for s in ("Critical", "High", "Medium", "Low", "None", "Not Scored"):
            cvss_severity_counts.setdefault(s, 0)

        # Maximum CVSS Base Score observed across active findings
        cursor.execute("""
            SELECT MAX(cvss_score) FROM findings
            WHERE status IN ('FAIL', 'WARNING') AND cvss_score IS NOT NULL
        """)
        max_cvss_row = cursor.fetchone()
        max_cvss_score = round(max_cvss_row[0] or 0.0, 1)

        # Category distribution
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM findings
            WHERE status IN ('FAIL', 'WARNING')
            GROUP BY category
            ORDER BY count DESC
        """)
        category_counts = {row["category"]: row["count"] for row in cursor.fetchall()}

        # Activity over time (scans grouped by date YYYY-MM-DD)
        cursor.execute("""
            SELECT SUBSTR(timestamp, 1, 10) as scan_date, COUNT(*) as count, AVG(score) as avg_score
            FROM scans
            GROUP BY scan_date
            ORDER BY scan_date ASC
            LIMIT 30
        """)
        activity_over_time = [
            {"date": r["scan_date"], "count": r["count"], "avg_score": round(r["avg_score"] or 0.0, 1)}
            for r in cursor.fetchall()
        ]

        # Count of resolved findings
        cursor.execute("SELECT COUNT(*) FROM findings WHERE verification_status IN ('Fixed', 'Verified')")
        resolved_count = cursor.fetchone()[0] or 0

        # High priority gap count (Critical + High)
        cursor.execute("SELECT SUM(critical_high_count) FROM scans")
        critical_high_total = cursor.fetchone()[0] or 0

        # Remediation task counts
        cursor.execute("SELECT status, COUNT(*) FROM remediation_tasks GROUP BY status")
        task_counts = {r[0]: r[1] for r in cursor.fetchall()}
        open_tasks = task_counts.get("Open", 0) + task_counts.get("In Progress", 0)

        # Average CVSS Base Score across scans
        cursor.execute("SELECT AVG(max_cvss_score) FROM scans WHERE max_cvss_score IS NOT NULL")
        avg_cvss_row = cursor.fetchone()
        avg_cvss_score = round(avg_cvss_row[0] or 0.0, 1)

        return {
            "total_scans": total_scans,
            "unique_targets": unique_targets,
            "avg_score": avg_score,
            "avg_cvss_score": avg_cvss_score,
            "latest_scan": latest_scan,
            "severity_counts": severity_counts,
            "cvss_severity_counts": cvss_severity_counts,
            "cvss_severity_distribution": cvss_severity_counts,
            "max_cvss_score": max_cvss_score,
            "category_counts": category_counts,
            "activity_over_time": activity_over_time,
            "resolved_count": resolved_count,
            "critical_high_total": critical_high_total,
            "open_remediation_tasks": open_tasks,
            "task_counts": task_counts,
        }


def get_remediation_tasks(target_host: Optional[str] = None, status_filter: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve actionable remediation checklist tasks with optional filtering."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM remediation_tasks WHERE 1=1"
        params = []
        if target_host:
            query += " AND target_host = ?"
            params.append(target_host)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        query += " ORDER BY id DESC"
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


def update_remediation_status(task_id: int, new_status: str, notes: str = "", db_path: Optional[str] = None) -> bool:
    """Update task lifecycle state (Open, In Progress, Fixed, Verified)."""
    valid_states = ("Open", "In Progress", "Fixed", "Verified")
    if new_status not in valid_states:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_states}")

    init_db(db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE remediation_tasks
            SET status = ?, notes = ?, updated_at = ?
            WHERE id = ?
        """, (new_status, notes, now, task_id))
        conn.commit()
        return cursor.rowcount > 0


def get_distinct_hosts(db_path: Optional[str] = None) -> List[str]:
    """Retrieve list of distinct hostnames audited."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT hostname FROM scans ORDER BY hostname ASC")
        return [r[0] for r in cursor.fetchall()]


def search_findings(
    query: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[int] = None,
    limit: int = 200,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Search and filter findings across scans."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        sql = """
            SELECT f.*, s.hostname, s.timestamp as scan_timestamp
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE 1=1
        """
        params = []
        if scan_id:
            sql += " AND f.scan_id = ?"
            params.append(scan_id)
        if query:
            sql += " AND (f.title LIKE ? OR f.evidence LIKE ? OR f.recommended_action LIKE ? OR s.hostname LIKE ?)"
            pattern = f"%{query}%"
            params.extend([pattern, pattern, pattern, pattern])
        if severity and severity != "All":
            sql += " AND f.severity = ?"
            params.append(severity)
        if category and category != "All":
            sql += " AND f.category = ?"
            params.append(category)
        if status and status != "All":
            sql += " AND f.status = ?"
            params.append(status)

        sql += " ORDER BY f.id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


def seed_demo_history(db_path: Optional[str] = None):
    """Seed realistic demonstration audit records with authentic CVSS v3.0 scores if DB is empty."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        if cursor.fetchone()[0] > 0:
            return  # Already has records

    # Use existing core.database seed logic if empty
    from core.database import seed_demo_history as core_seed
    core_seed(get_db_path(db_path))
