"""End-to-End Complete Integration Test for GOVNEXIS.

Tests the complete lifecycle:
1. Initialize SQLite database
2. Start isolated local demo server on port 8765
3. Audit baseline (misconfigured) state
4. Save baseline scan record and auto-generate remediation tasks
5. Verify remediation tasks exist
6. Apply hardened configuration state
7. Audit hardened state
8. Save verification scan record
9. Verify score improvement delta
10. Generate PDF, HTML, JSON, and CSV reports and verify file contents
"""

import os
import tempfile
import pytest

from core.config import LOCAL_DEMO_URL
from core.mock_site import (
    start_mock_server, stop_mock_server, DEMO_STATE, MockServerState
)
from core.scanner import execute_scan
from core.database import (
    init_db, save_scan, get_scan, get_all_scans,
    get_remediation_tasks, update_remediation_status, get_scan_trends
)
from core.reports import (
    generate_json_report, generate_html_report,
    generate_csv_report, generate_pdf_report
)


@pytest.fixture(scope="module", autouse=True)
def run_demo_server():
    """Ensure mock server is running for this module."""
    start_mock_server()
    yield
    stop_mock_server()


def test_full_govnexis_lifecycle():
    """Run through the entire end-to-end hackathon demonstration workflow."""
    fd, test_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(test_db)

    try:
        # Step 1: Baseline Scan (Misconfigured state)
        DEMO_STATE.set_mode(MockServerState.MODE_BASELINE)
        baseline_result = execute_scan(
            target_url=LOCAL_DEMO_URL,
            user_confirmed_authorization=True,
            allow_local_demo=True
        )
        assert baseline_result.status_code == 200
        baseline_score = baseline_result.score_report.final_score
        assert baseline_score < 60  # Baseline has critical missing headers

        # Step 2: Persist Baseline Scan to Database
        scan_id_1 = save_scan(baseline_result, db_path=test_db)
        assert scan_id_1 > 0

        # Step 3: Check Remediation Checklist auto-creation
        tasks = get_remediation_tasks(target_host=baseline_result.hostname, db_path=test_db)
        assert len(tasks) >= 3  # CSP, HSTS, Cookies, etc.
        assert all(t["status"] == "Open" for t in tasks)

        # Mark one task as in progress
        update_remediation_status(tasks[0]["id"], "In Progress", "Working with web team", db_path=test_db)

        # Step 4: Apply Demo Fixes (Switch to Hardened State)
        DEMO_STATE.set_mode(MockServerState.MODE_HARDENED)

        # Step 5: Follow-up Verification Rescan
        hardened_result = execute_scan(
            target_url=LOCAL_DEMO_URL,
            user_confirmed_authorization=True,
            allow_local_demo=True
        )
        hardened_score = hardened_result.score_report.final_score
        assert hardened_score >= 90  # Hardened should achieve Grade A

        # Step 6: Persist Rescan
        scan_id_2 = save_scan(hardened_result, db_path=test_db)
        assert scan_id_2 > scan_id_1

        # Step 7: Verify Score Delta
        score_delta = hardened_score - baseline_score
        assert score_delta >= 40

        # Step 8: Verify Dashboard Trends Aggregation
        trends = get_scan_trends(db_path=test_db)
        assert trends["total_scans"] == 2
        assert trends["unique_targets"] == 1
        assert trends["latest_scan"]["score"] == hardened_score

        # Step 9: Generate Multi-Format Reports from Verification Scan
        scan_dict = hardened_result.to_dict()

        # HTML
        html_out = generate_html_report(scan_dict)
        assert "GOVNEXIS" in html_out
        assert "CVSS v3.0 Base Score" in html_out

        # JSON
        json_out = generate_json_report(scan_dict)
        assert "GOVNEXIS" in json_out

        # CSV
        csv_out = generate_csv_report(scan_dict)
        assert "GOVNEXIS" in csv_out

        # PDF
        pdf_out = generate_pdf_report(scan_dict)
        assert pdf_out.startswith(b"%PDF")
        assert len(pdf_out) > 1000

    finally:
        import gc
        gc.collect()
        if os.path.exists(test_db):
            try:
                os.remove(test_db)
            except PermissionError:
                pass
