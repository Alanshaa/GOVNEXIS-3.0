"""SQLite Persistence Engine for GOVNEXIS.

Stores:
- Complete scan execution history & metrics
- Audited findings records with CVSS v3.0 base scores, vectors, and compliance tags
- Remediation task tracking with verification lifecycle
- Aggregated metrics and trend calculations for executive dashboards
- Backward-compatible schema migrations
"""

import sqlite3
import json
import datetime
from typing import Dict, List, Any, Optional
from core.config import (
    DATABASE_PATH, STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)
from core.scanner import ScanResult
from core.cvss import assign_finding_cvss, CVSSScore


def get_connection(db_path: str = DATABASE_PATH) -> sqlite3.Connection:
    """Create and return a database connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DATABASE_PATH):
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

        # Safe migration for CVSS columns if database was created by previous version
        cursor.execute("PRAGMA table_info(scans)")
        existing_scan_cols = [row["name"] for row in cursor.fetchall()]
        if "max_cvss_score" not in existing_scan_cols:
            cursor.execute("ALTER TABLE scans ADD COLUMN max_cvss_score REAL DEFAULT 0.0")
        if "max_cvss_severity" not in existing_scan_cols:
            cursor.execute("ALTER TABLE scans ADD COLUMN max_cvss_severity TEXT DEFAULT 'None'")

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

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_target ON remediation_tasks(target_host);")
        conn.commit()


def save_scan(scan_result: ScanResult, db_path: str = DATABASE_PATH) -> int:
    """Persist a completed scan result and its individual findings into SQLite."""
    init_db(db_path)

    # Calculate status counts
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


def get_scan(scan_id: int, db_path: str = DATABASE_PATH) -> Optional[Dict[str, Any]]:
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


def get_all_scans(limit: int = 100, db_path: str = DATABASE_PATH) -> List[Dict[str, Any]]:
    """Retrieve list of scans ordered by most recent first, with CVSS v3.0 metrics."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
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


def delete_scan(scan_id: int, db_path: str = DATABASE_PATH) -> bool:
    """Delete a scan and its associated findings."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def delete_all_scans(db_path: str = DATABASE_PATH):
    """Clear all scans and findings from database."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings")
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM remediation_tasks")
        conn.commit()


def get_scan_trends(db_path: str = DATABASE_PATH) -> Dict[str, Any]:
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

        # Configuration severity counts (legacy compliance breakdown)
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

        return {
            "total_scans": total_scans,
            "unique_targets": unique_targets,
            "avg_score": avg_score,
            "latest_scan": latest_scan,
            "severity_counts": severity_counts,
            "cvss_severity_counts": cvss_severity_counts,
            "cvss_severity_distribution": cvss_severity_counts,
            "max_cvss_score": max_cvss_score,
            "category_counts": category_counts,
            "activity_over_time": activity_over_time,
            "resolved_count": resolved_count,
            "critical_high_total": critical_high_total,
        }


def get_remediation_tasks(target_host: Optional[str] = None, db_path: str = DATABASE_PATH) -> List[Dict[str, Any]]:
    """Retrieve actionable remediation checklist tasks."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        if target_host:
            cursor.execute("SELECT * FROM remediation_tasks WHERE target_host = ? ORDER BY id DESC", (target_host,))
        else:
            cursor.execute("SELECT * FROM remediation_tasks ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]


def update_remediation_status(task_id: int, new_status: str, notes: str = "", db_path: str = DATABASE_PATH) -> bool:
    """Update task lifecycle state (Open, In Progress, Fixed, Verified)."""
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


def seed_demo_history(db_path: str = DATABASE_PATH):
    """Seed realistic demonstration audit records with authentic CVSS v3.0 scores."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        if cursor.fetchone()[0] > 0:
            return  # Already has records

    dates = [
        "2026-10-09T14:20:00Z",
        "2026-10-10T11:05:00Z",
        "2026-10-11T16:45:00Z",
    ]

    # Scan 1: Baseline City Hall Portal (Score 35)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        raw_s1 = json.dumps({
            "target_url": "https://portal.citygov.example.gov",
            "final_url": "https://portal.citygov.example.gov",
            "hostname": "portal.citygov.example.gov",
            "timestamp": dates[0],
            "status_code": 200,
            "resolved_ips": ["198.51.100.10"],
            "score_report": {
                "final_score": 35,
                "letter_grade": "F",
                "critical_high_count": 4,
                "max_cvss_score": 6.8,
                "cvss_severity_distribution": {"Critical": 0, "High": 0, "Medium": 3, "Low": 0, "None": 0, "Not Scored": 2}
            },
            "response_headers": {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"}
        })
        cursor.execute("""
            INSERT INTO scans (
                target_url, final_url, hostname, timestamp, score, letter_grade,
                status_code, duration_ms, is_demo, total_checks, passed_checks,
                failed_checks, warning_checks, not_assessed_checks,
                critical_high_count, raw_json
            ) VALUES (
                'https://portal.citygov.example.gov', 'https://portal.citygov.example.gov', 'portal.citygov.example.gov',
                ?, 35, 'F', 200, 340, 1, 10, 2, 6, 2, 0, 4, ?
            )
        """, (dates[0], raw_s1))
        s1 = cursor.lastrowid

        sample_findings = [
            (s1, "content_security_policy", "Content-Security-Policy (CSP)", "Injection Defense", SEV_HIGH, STATUS_FAIL, "Header absent", "Open"),
            (s1, "hsts_header", "HTTP Strict Transport Security (HSTS)", "Transport Layer Security", SEV_HIGH, STATUS_FAIL, "Header absent", "Open"),
            (s1, "x_frame_options", "Clickjacking Defense", "UI Redressing", SEV_MEDIUM, STATUS_FAIL, "Missing XFO", "Open"),
            (s1, "secure_cookies", "Cookie Security Attributes", "Session Integrity", SEV_MEDIUM, STATUS_FAIL, "Missing HttpOnly and Secure", "Open"),
            (s1, "server_disclosure", "Server Information Disclosure", "Information Disclosure", SEV_LOW, STATUS_FAIL, "Apache/2.4.41 leaked", "Open"),
        ]
        for f in sample_findings:
            cvss = assign_finding_cvss(f[1], f[5], f[6], f[4])
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, check_id, title, category, severity, status, evidence,
                    why_it_matters, potential_impact, recommended_action, verification_status,
                    cvss_score, cvss_severity, cvss_vector, cvss_status, cvss_unscored_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Critical header', 'Risk', 'Fix config', ?, ?, ?, ?, ?, ?)
            """, (
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                cvss.base_score, cvss.severity, cvss.vector_string, cvss.status, cvss.unscored_reason
            ))

        # Scan 2: State Health Portal (Score 65)
        raw_s2 = json.dumps({
            "target_url": "https://health.agency.example.gov",
            "final_url": "https://health.agency.example.gov",
            "hostname": "health.agency.example.gov",
            "timestamp": dates[1],
            "status_code": 200,
            "resolved_ips": ["198.51.100.20"],
            "score_report": {
                "final_score": 65,
                "letter_grade": "D",
                "critical_high_count": 2,
                "max_cvss_score": 4.2,
                "cvss_severity_distribution": {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "None": 1, "Not Scored": 1}
            },
            "response_headers": {"server": "nginx/1.18.0", "strict-transport-security": "max-age=86400"}
        })
        cursor.execute("""
            INSERT INTO scans (
                target_url, final_url, hostname, timestamp, score, letter_grade,
                status_code, duration_ms, is_demo, total_checks, passed_checks,
                failed_checks, warning_checks, not_assessed_checks,
                critical_high_count, raw_json
            ) VALUES (
                'https://health.agency.example.gov', 'https://health.agency.example.gov', 'health.agency.example.gov',
                ?, 65, 'D', 200, 410, 1, 10, 5, 3, 2, 0, 2, ?
            )
        """, (dates[1], raw_s2))
        s2 = cursor.lastrowid
        f2_data = [
            (s2, "hsts_header", "HTTP Strict Transport Security (HSTS)", "Transport Layer Security", SEV_MEDIUM, STATUS_WARNING, "max-age=86400 is less than 1 year", "Open"),
            (s2, "x_frame_options", "Clickjacking Defense", "UI Redressing", SEV_INFO, STATUS_PASS, "X-Frame-Options: SAMEORIGIN", "Verified"),
        ]
        for f in f2_data:
            cvss = assign_finding_cvss(f[1], f[5], f[6], f[4])
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, check_id, title, category, severity, status, evidence,
                    why_it_matters, potential_impact, recommended_action, verification_status,
                    cvss_score, cvss_severity, cvss_vector, cvss_status, cvss_unscored_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Standard compliance', 'Impact', 'Action', ?, ?, ?, ?, ?, ?)
            """, (
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                cvss.base_score, cvss.severity, cvss.vector_string, cvss.status, cvss.unscored_reason
            ))

        # Scan 3: Modernized Municipal Service (Score 92)
        raw_s3 = json.dumps({
            "target_url": "https://services.state.example.gov",
            "final_url": "https://services.state.example.gov",
            "hostname": "services.state.example.gov",
            "timestamp": dates[2],
            "status_code": 200,
            "resolved_ips": ["198.51.100.30"],
            "score_report": {
                "final_score": 92,
                "letter_grade": "A",
                "critical_high_count": 0,
                "max_cvss_score": 0.0,
                "cvss_severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 4, "Not Scored": 0}
            },
            "response_headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff"
            }
        })
        cursor.execute("""
            INSERT INTO scans (
                target_url, final_url, hostname, timestamp, score, letter_grade,
                status_code, duration_ms, is_demo, total_checks, passed_checks,
                failed_checks, warning_checks, not_assessed_checks,
                critical_high_count, raw_json
            ) VALUES (
                'https://services.state.example.gov', 'https://services.state.example.gov', 'services.state.example.gov',
                ?, 92, 'A', 200, 290, 1, 10, 8, 0, 2, 0, 0, ?
            )
        """, (dates[2], raw_s3))
        s3 = cursor.lastrowid
        f3_data = [
            (s3, "hsts_header", "HTTP Strict Transport Security (HSTS)", "Transport Layer Security", SEV_INFO, STATUS_PASS, "max-age=31536000; includeSubDomains; preload", "Verified"),
            (s3, "content_security_policy", "Content-Security-Policy (CSP)", "Injection Defense", SEV_INFO, STATUS_PASS, "default-src 'self'", "Verified"),
            (s3, "x_frame_options", "Clickjacking Defense", "UI Redressing", SEV_INFO, STATUS_PASS, "X-Frame-Options: DENY", "Verified"),
            (s3, "x_content_type_options", "MIME-Sniffing Defense", "Content Handling", SEV_INFO, STATUS_PASS, "X-Content-Type-Options: nosniff", "Verified"),
        ]
        for f in f3_data:
            cvss = assign_finding_cvss(f[1], f[5], f[6], f[4])
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, check_id, title, category, severity, status, evidence,
                    why_it_matters, potential_impact, recommended_action, verification_status,
                    cvss_score, cvss_severity, cvss_vector, cvss_status, cvss_unscored_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Hardened standard', 'None', 'Keep active', ?, ?, ?, ?, ?, ?)
            """, (
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                cvss.base_score, cvss.severity, cvss.vector_string, cvss.status, cvss.unscored_reason
            ))

        conn.commit()
