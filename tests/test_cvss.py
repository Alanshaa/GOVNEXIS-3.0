"""Unit and Integration Tests for Official CVSS v3.0 Implementation in GOVNEXIS.

Covers:
1. Official FIRST CVSS v3.0 reference example vectors (Heartbleed, Shellshock, XSS, Scope transitions)
2. Metric validation and error handling
3. Scope-dependent privilege weighting and score multipliers
4. Official CVSS v3.0 Roundup behavior and boundary rounding
5. Vector string building, formatting, and parsing
6. FindingRecord and ScoreReport integration
7. Defensible mapping of GOVNEXIS checks and 'Not Scored' defense-in-depth designations
8. Persistence and migration in SQLite database
"""

import pytest
import sqlite3
import tempfile
import os

from core.cvss import (
    calculate_cvss30_base_score,
    get_cvss30_severity,
    cvss30_roundup,
    build_cvss30_vector,
    parse_cvss30_vector,
    assign_finding_cvss,
    CVSSScore,
    SEV_NONE,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL,
)
from core.security_checks import FindingRecord
from core.scoring import compute_security_score
from core.database import init_db, save_scan, get_scan, get_scan_trends
from core.scanner import ScanResult
from core.reports import generate_csv_report, generate_html_report, generate_pdf_report, generate_json_report


# ============================================================================
# 1. Official FIRST CVSS v3.0 Reference Vectors
# ============================================================================

def test_cvss30_heartbleed_reference():
    """CVE-2014-0160 (Heartbleed): Official FIRST Base Score = 7.5 High.
    Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    """
    score = calculate_cvss30_base_score(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"
    )
    assert score == 7.5
    assert get_cvss30_severity(score) == SEV_HIGH
    vec = build_cvss30_vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
    assert vec == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_cvss30_shellshock_reference():
    """CVE-2014-6271 (Shellshock): Official FIRST Base Score = 9.8 Critical.
    Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    score = calculate_cvss30_base_score(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert score == 9.8
    assert get_cvss30_severity(score) == SEV_CRITICAL


def test_cvss30_struts_scope_changed_reference():
    """Apache Struts RCE with Scope Changed: Official FIRST Base Score = 10.0 Critical.
    Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    """
    score = calculate_cvss30_base_score(
        av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
    )
    assert score == 10.0
    assert get_cvss30_severity(score) == SEV_CRITICAL


def test_cvss30_reflected_xss_reference():
    """Reflected XSS with Scope Changed: Official FIRST Base Score = 6.1 Medium.
    Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    """
    score = calculate_cvss30_base_score(
        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
    )
    assert score == 6.1
    assert get_cvss30_severity(score) == SEV_MEDIUM


def test_cvss30_scope_changed_with_privileges_required():
    """Scope Changed with High Privileges: Official FIRST Base Score = 9.1 Critical.
    Tests Scope-dependent PR weight (PR:H with S:C is 0.50, vs 0.27 when S:U).
    Vector: CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
    """
    score_changed = calculate_cvss30_base_score(
        av="N", ac="L", pr="H", ui="N", s="C", c="H", i="H", a="H"
    )
    assert score_changed == 9.1
    assert get_cvss30_severity(score_changed) == SEV_CRITICAL

    # Compare with Scope Unchanged (PR:H with S:U is 0.27)
    score_unchanged = calculate_cvss30_base_score(
        av="N", ac="L", pr="H", ui="N", s="U", c="H", i="H", a="H"
    )
    assert score_unchanged == 7.2
    assert get_cvss30_severity(score_unchanged) == SEV_HIGH


def test_cvss30_zero_impact():
    """When Impact <= 0 (all CIA metrics are None), Base Score must be exactly 0.0 None."""
    score = calculate_cvss30_base_score(
        av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"
    )
    assert score == 0.0
    assert get_cvss30_severity(score) == SEV_NONE


# ============================================================================
# 2. Official Rounding Rules and Severity Boundaries
# ============================================================================

def test_cvss30_roundup():
    """Test official CVSS v3.0 Roundup specification."""
    # 4.02 rounds up to 4.1
    assert cvss30_roundup(4.02) == 4.1
    # 4.00 stays 4.0
    assert cvss30_roundup(4.00) == 4.0
    # 0.0 stays 0.0
    assert cvss30_roundup(0.0) == 0.0
    # 7.41 rounds up to 7.5
    assert cvss30_roundup(7.41) == 7.5


def test_cvss30_severity_boundaries():
    """Test official CVSS v3.0 severity boundary cutoffs."""
    assert get_cvss30_severity(0.0) == "None"
    assert get_cvss30_severity(0.1) == "Low"
    assert get_cvss30_severity(3.9) == "Low"
    assert get_cvss30_severity(4.0) == "Medium"
    assert get_cvss30_severity(6.9) == "Medium"
    assert get_cvss30_severity(7.0) == "High"
    assert get_cvss30_severity(8.9) == "High"
    assert get_cvss30_severity(9.0) == "Critical"
    assert get_cvss30_severity(10.0) == "Critical"


# ============================================================================
# 3. Metric Validation & Error Handling
# ============================================================================

def test_invalid_metric_values_raise_error():
    """Invalid metric keys or values must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid Attack Vector"):
        calculate_cvss30_base_score(av="X", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")

    with pytest.raises(ValueError, match="Invalid Scope"):
        calculate_cvss30_base_score(av="N", ac="L", pr="N", ui="N", s="Z", c="H", i="N", a="N")

    with pytest.raises(ValueError, match="Invalid Privileges Required"):
        calculate_cvss30_base_score(av="N", ac="L", pr="UNKNOWN", ui="N", s="U", c="H", i="N", a="N")


# ============================================================================
# 4. Vector Generation & Parsing
# ============================================================================

def test_vector_parsing_and_roundtrip():
    """Test parsing a standard CVSS v3.0 vector string and reconstructing it."""
    orig_vector = "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
    metrics = parse_cvss30_vector(orig_vector)
    assert metrics["AV"] == "N"
    assert metrics["AC"] == "H"
    assert metrics["PR"] == "N"
    assert metrics["UI"] == "R"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"
    assert metrics["I"] == "H"
    assert metrics["A"] == "N"

    rebuilt = build_cvss30_vector(
        av=metrics["AV"], ac=metrics["AC"], pr=metrics["PR"], ui=metrics["UI"],
        s=metrics["S"], c=metrics["C"], i=metrics["I"], a=metrics["A"]
    )
    assert rebuilt == orig_vector


def test_malformed_vector_parsing():
    """Invalid vector formats must raise ValueError."""
    with pytest.raises(ValueError):
        parse_cvss30_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

    with pytest.raises(ValueError):
        parse_cvss30_vector("INVALID_STRING_WITHOUT_METRICS")


# ============================================================================
# 5. Defensible Findings Mapping & 'Not Scored' Behavior
# ============================================================================

def test_scored_checks_mapping():
    """Supported vulnerability checks with demonstrable attack vectors must produce valid CVSS scores."""
    # HTTPS missing
    cvss_https = assign_finding_cvss("https_enforced", "FAIL", "Plaintext HTTP", "High")
    assert cvss_https.status == "SCORED"
    assert cvss_https.base_score == 7.4
    assert cvss_https.severity == "High"
    assert "AV:N/AC:H" in cvss_https.vector_string

    # HSTS missing
    cvss_hsts = assign_finding_cvss("hsts_header", "FAIL", "Header absent", "High")
    assert cvss_hsts.status == "SCORED"
    assert cvss_hsts.base_score == 6.8
    assert cvss_hsts.severity == "Medium"

    # Clickjacking / XFO missing
    cvss_xfo = assign_finding_cvss("clickjacking_defense", "FAIL", "Header absent", "Medium")
    assert cvss_xfo.status == "SCORED"
    assert cvss_xfo.base_score == 4.3
    assert cvss_xfo.severity == "Medium"

    # Insecure Cookie
    cvss_cookie = assign_finding_cvss("cookie_security", "FAIL", "Missing Secure flag", "High")
    assert cvss_cookie.status == "SCORED"
    assert cvss_cookie.base_score == 5.3
    assert cvss_cookie.severity == "Medium"

    # Server Disclosure
    cvss_server = assign_finding_cvss("server_disclosure", "WARNING", "Server: Apache/2.4.41", "Low")
    assert cvss_server.status == "SCORED"
    assert cvss_server.base_score == 5.3
    assert cvss_server.severity == "Medium"


def test_unscored_defense_in_depth_checks():
    """Defense-in-depth headers without verified exploit chains must be marked Not Scored."""
    # Content-Security-Policy
    cvss_csp = assign_finding_cvss("content_security_policy", "FAIL", "CSP header absent", "High")
    assert cvss_csp.status == "NOT_SCORED"
    assert cvss_csp.base_score is None
    assert cvss_csp.severity == "Not Scored"
    assert "defense-in-depth" in cvss_csp.unscored_reason.lower()
    assert "xss" in cvss_csp.unscored_reason.lower()

    # Permissions-Policy
    cvss_perm = assign_finding_cvss("permissions_policy", "FAIL", "Header absent", "Low")
    assert cvss_perm.status == "NOT_SCORED"
    assert cvss_perm.base_score is None

    # Referrer-Policy
    cvss_ref = assign_finding_cvss("referrer_policy", "FAIL", "Header absent", "Low")
    assert cvss_ref.status == "NOT_SCORED"

    # MIME-Sniffing
    cvss_mime = assign_finding_cvss("x_content_type_options", "FAIL", "Header absent", "Low")
    assert cvss_mime.status == "NOT_SCORED"


def test_passing_checks_have_zero_cvss():
    """Passing checks should have CVSS 0.0 None."""
    cvss_pass = assign_finding_cvss("https_enforced", "PASS", "HTTPS active", "Informational")
    assert cvss_pass.status == "SCORED"
    assert cvss_pass.base_score == 0.0
    assert cvss_pass.severity == "None"


# ============================================================================
# 6. Integration with FindingRecord & ScoreReport
# ============================================================================

def test_finding_record_auto_evaluates_cvss():
    """FindingRecord automatically assigns CVSSScore upon initialization."""
    finding = FindingRecord(
        check_id="https_enforced",
        title="HTTP Encryption",
        category="Transport",
        status="FAIL",
        severity="High",
        evidence="HTTP plaintext",
        why_it_matters="MITM danger",
        potential_impact="Data theft",
        recommended_action="Enable HTTPS",
    )
    assert finding.cvss is not None
    assert finding.cvss.base_score == 7.4
    assert finding.cvss.severity == "High"

    as_dict = finding.to_dict()
    assert "cvss" in as_dict
    assert as_dict["cvss"]["base_score"] == 7.4
    assert as_dict["cvss"]["vector_string"].startswith("CVSS:3.0/")


def test_score_report_aggregates_cvss_metrics():
    """compute_security_score calculates max CVSS and severity distribution."""
    f1 = FindingRecord(
        check_id="https_enforced", title="HTTPS", category="Transport",
        status="FAIL", severity="High", evidence="Plaintext",
        why_it_matters="", potential_impact="", recommended_action=""
    )
    f2 = FindingRecord(
        check_id="content_security_policy", title="CSP", category="Injection",
        status="FAIL", severity="High", evidence="Absent",
        why_it_matters="", potential_impact="", recommended_action=""
    )
    f3 = FindingRecord(
        check_id="hsts_header", title="HSTS", category="Transport",
        status="PASS", severity="Informational", evidence="Present",
        why_it_matters="", potential_impact="", recommended_action=""
    )

    report = compute_security_score([f1, f2, f3])
    # HTTPS score is 7.4 High -> max CVSS should be 7.4
    assert report.max_cvss_score == 7.4
    assert report.scored_vulnerabilities_count == 1
    assert report.unscored_findings_count == 1
    assert report.cvss_severity_distribution["High"] == 1
    assert report.cvss_severity_distribution["Not Scored"] == 1


# ============================================================================
# 7. Database Migration & Stored Scan Persistence
# ============================================================================

def test_database_persistence_and_cvss_migration():
    """Verify scan and findings tables persist CVSS columns and migrations safely."""
    import shutil
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "test_govnexis.db")

    try:
        init_db(temp_db)

        # Create scan result with CVSS
        f1 = FindingRecord(
            check_id="https_enforced", title="HTTPS", category="Transport",
            status="FAIL", severity="High", evidence="Plaintext",
            why_it_matters="", potential_impact="", recommended_action=""
        )
        f2 = FindingRecord(
            check_id="content_security_policy", title="CSP", category="Injection",
            status="FAIL", severity="High", evidence="Absent",
            why_it_matters="", potential_impact="", recommended_action=""
        )
        score_rep = compute_security_score([f1, f2])

        scan_res = ScanResult(
            target_url="https://test.gov",
            final_url="http://test.gov",
            hostname="test.gov",
            resolved_ips=["1.2.3.4"],
            status_code=200,
            response_headers={},
            cookies=[],
            tls_info={},
            findings=[f1, f2],
            score_report=score_rep,
            duration_ms=120,
            timestamp="2026-10-14T12:00:00Z",
            is_demo=False
        )

        scan_id = save_scan(scan_res, db_path=temp_db)
        loaded = get_scan(scan_id, db_path=temp_db)
        assert loaded is not None

        # Verify loaded findings have CVSS fields
        findings = loaded["findings"]
        assert len(findings) == 2

        f_https = next(f for f in findings if f["check_id"] == "https_enforced")
        assert f_https["cvss_score"] == 7.4
        assert f_https["cvss_severity"] == "High"
        assert f_https["cvss_status"] == "SCORED"
        assert "CVSS:3.0" in f_https["cvss_vector"]

        f_csp = next(f for f in findings if f["check_id"] == "content_security_policy")
        assert f_csp["cvss_status"] == "NOT_SCORED"
        assert f_csp["cvss_score"] is None
        assert "defense-in-depth" in f_csp["cvss_unscored_reason"].lower()

        # Check trends aggregation
        trends = get_scan_trends(db_path=temp_db)
        assert trends["max_cvss_score"] == 7.4
        assert "High" in trends["cvss_severity_distribution"]

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================================================
# 8. Report Formats Verification
# ============================================================================

def test_reports_contain_cvss_data():
    """Verify JSON, CSV, HTML, and PDF reports all include CVSS data."""
    f1 = FindingRecord(
        check_id="https_enforced", title="HTTPS Check", category="Transport",
        status="FAIL", severity="High", evidence="No HTTPS",
        why_it_matters="", potential_impact="", recommended_action=""
    )
    score_rep = compute_security_score([f1])
    scan_res = ScanResult(
        target_url="https://audit.gov",
        final_url="http://audit.gov",
        hostname="audit.gov",
        resolved_ips=["1.2.3.4"],
        status_code=200,
        response_headers={},
        cookies=[],
        tls_info={},
        findings=[f1],
        score_report=score_rep,
        duration_ms=150,
        timestamp="2026-10-14T12:00:00Z",
        is_demo=False
    )
    scan_dict = scan_res.to_dict()

    # JSON report
    json_out = generate_json_report(scan_dict)
    assert "max_cvss_score" in json_out
    assert "cvss" in json_out

    # CSV report
    csv_out = generate_csv_report(scan_dict)
    assert "CVSS Base Score" in csv_out
    assert "7.4" in csv_out
    assert "CVSS:3.0" in csv_out

    # HTML report
    html_out = generate_html_report(scan_dict)
    assert "Max CVSS" in html_out
    assert "7.4" in html_out
    assert "CVSS v3.0 Severity" in html_out

    # PDF report
    pdf_out = generate_pdf_report(scan_dict)
    assert isinstance(pdf_out, bytes)
    assert len(pdf_out) > 500
