"""Unit Tests for SQLite Persistence and Aggregations."""

import gc
import os
import tempfile
import pytest

from core.database import (
    init_db, save_scan, get_scan, get_all_scans,
    delete_scan, delete_all_scans, get_scan_trends,
    get_remediation_tasks, update_remediation_status
)
from core.scanner import ScanResult
from core.security_checks import FindingRecord
from core.scoring import ScoreReport


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database file for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    gc.collect()
    if os.path.exists(path):
        try:
            os.remove(path)
        except PermissionError:
            pass


def test_save_and_retrieve_scan(temp_db):
    """Verify persisting and reading a scan result."""
    findings = [
        FindingRecord(
            check_id="hsts_header",
            title="HSTS",
            category="Transport Layer Security",
            status="FAIL",
            severity="High",
            evidence="Header absent",
            why_it_matters="Downgrade attacks",
            potential_impact="Traffic interception",
            recommended_action="Set Strict-Transport-Security"
        )
    ]
    score_rep = ScoreReport(
        final_score=60,
        letter_grade="D",
        total_possible_points=100,
        earned_points=60.0,
        breakdown=[],
        critical_high_count=1,
        summary_statement="Test",
        methodology_notes="Test methodology"
    )
    result = ScanResult(
        target_url="https://agency.example.gov",
        final_url="https://agency.example.gov",
        hostname="agency.example.gov",
        resolved_ips=["93.184.216.34"],
        status_code=200,
        response_headers={"server": "nginx"},
        cookies=[],
        tls_info=None,
        findings=findings,
        score_report=score_rep,
        duration_ms=150,
        timestamp="2026-10-12T12:00:00Z",
        is_demo=False
    )

    scan_id = save_scan(result, db_path=temp_db)
    assert scan_id > 0

    retrieved = get_scan(scan_id, db_path=temp_db)
    assert retrieved is not None
    assert retrieved["hostname"] == "agency.example.gov"
    assert retrieved["score"] == 60
    assert len(retrieved["findings"]) == 1

    # Trends check
    trends = get_scan_trends(db_path=temp_db)
    assert trends["total_scans"] == 1
    assert trends["unique_targets"] == 1
    assert trends["avg_score"] == 60.0


def test_remediation_lifecycle(temp_db):
    """Verify auto-generation and status tracking of remediation tasks."""
    findings = [
        FindingRecord(
            check_id="content_security_policy",
            title="CSP",
            category="Injection Defense",
            status="FAIL",
            severity="High",
            evidence="Header absent",
            why_it_matters="XSS",
            potential_impact="Script execution",
            recommended_action="Add CSP"
        )
    ]
    score_rep = ScoreReport(50, "F", 100, 50.0, [], 1, "", "")
    result = ScanResult(
        "https://site.gov", "https://site.gov", "site.gov",
        ["1.1.1.1"], 200, {}, [], None, findings, score_rep, 100, "2026-10-12T12:00:00Z"
    )

    save_scan(result, db_path=temp_db)
    tasks = get_remediation_tasks(target_host="site.gov", db_path=temp_db)
    assert len(tasks) == 1
    assert tasks[0]["status"] == "Open"

    # Update lifecycle
    task_id = tasks[0]["id"]
    updated = update_remediation_status(task_id, "Fixed", "Applied in staging", db_path=temp_db)
    assert updated is True

    tasks_after = get_remediation_tasks(target_host="site.gov", db_path=temp_db)
    assert tasks_after[0]["status"] == "Fixed"
    assert tasks_after[0]["notes"] == "Applied in staging"


def test_delete_scan(temp_db):
    """Verify deleting a specific scan and wiping all scans."""
    findings = []
    score_rep = ScoreReport(100, "A", 100, 100.0, [], 0, "", "")
    result = ScanResult("https://a.gov", "https://a.gov", "a.gov", [], 200, {}, [], None, findings, score_rep, 50, "2026-10-12T12:00:00Z")

    s1 = save_scan(result, db_path=temp_db)
    s2 = save_scan(result, db_path=temp_db)

    assert len(get_all_scans(db_path=temp_db)) == 2

    # Delete single
    delete_scan(s1, db_path=temp_db)
    assert len(get_all_scans(db_path=temp_db)) == 1

    # Delete all
    delete_all_scans(db_path=temp_db)
    assert len(get_all_scans(db_path=temp_db)) == 0
