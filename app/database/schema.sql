-- GOVNEXIS 3.0 SQLite Database Schema
-- Stores scans, configuration findings, CVSS v3.0 vectors, and remediation tasks

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

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_host TEXT NOT NULL,
    check_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    notes TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);
CREATE INDEX IF NOT EXISTS idx_remediation_target ON remediation_tasks(target_host);
CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_tasks(status);
