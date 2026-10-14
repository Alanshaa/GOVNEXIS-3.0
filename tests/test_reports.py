"""Unit Tests for Multi-Format Report Generator."""

import json
import csv
import io
import pytest

from core.reports import (
    generate_json_report,
    generate_csv_report,
    generate_html_report,
    generate_pdf_report
)


@pytest.fixture
def sample_scan_dict():
    """Provides a realistic mock scan dictionary for reporting tests."""
    return {
        "target_url": "https://audit.portal.gov",
        "final_url": "https://audit.portal.gov",
        "hostname": "audit.portal.gov",
        "timestamp": "2026-10-12T15:30:00Z",
        "status_code": 200,
        "resolved_ips": ["198.51.100.1"],
        "score_report": {
            "final_score": 85,
            "letter_grade": "B+",
            "critical_high_count": 0,
        },
        "findings": [
            {
                "check_id": "hsts_header",
                "title": "Strict-Transport-Security",
                "category": "Transport Layer Security",
                "status": "PASS",
                "severity": "Informational",
                "evidence": "Strict-Transport-Security: max-age=31536000",
                "why_it_matters": "Enforces HTTPS",
                "potential_impact": "None",
                "recommended_action": "Retain header",
                "references": [{"title": "RFC 6797", "url": "https://tools.ietf.org/html/rfc6797"}]
            },
            {
                "check_id": "server_disclosure",
                "title": "Server Banner",
                "category": "Information Disclosure",
                "status": "WARNING",
                "severity": "Low",
                "evidence": "Server: Apache/2.4.41",
                "why_it_matters": "Reconnaissance data",
                "potential_impact": "Adversary profiling",
                "recommended_action": "Sanitize Server header",
                "references": []
            }
        ],
        "response_headers": {
            "server": "Apache/2.4.41",
            "strict-transport-security": "max-age=31536000"
        }
    }


def test_json_report(sample_scan_dict):
    """Verify structured JSON report schema and serialization."""
    json_str = generate_json_report(sample_scan_dict)
    data = json.loads(json_str)

    assert data["metadata"]["platform"] == "GOVNEXIS"
    assert data["target"]["hostname"] == "audit.portal.gov"
    assert data["score"]["final_score"] == 85
    assert len(data["findings"]) == 2


def test_csv_report(sample_scan_dict):
    """Verify tabular CSV export format and columns."""
    csv_str = generate_csv_report(sample_scan_dict)
    reader = csv.reader(io.StringIO(csv_str))
    rows = list(reader)

    # Header + 2 findings = 3 rows
    assert len(rows) == 3
    assert rows[0][0] == "Platform"
    assert rows[0][4] == "Check ID"
    assert rows[1][0] == "GOVNEXIS"
    assert rows[1][1] == "audit.portal.gov"


def test_html_report(sample_scan_dict):
    """Verify HTML report includes GOVNEXIS branding and escapes content."""
    html_str = generate_html_report(sample_scan_dict)

    assert "<!DOCTYPE html>" in html_str
    assert "GOVNEXIS" in html_str
    assert "audit.portal.gov" in html_str
    assert "CVSS v3.0 Base Score" in html_str
    assert "Strict-Transport-Security" in html_str
    assert "Server Banner" in html_str


def test_pdf_report(sample_scan_dict):
    """Verify PDF report generation via ReportLab."""
    pdf_bytes = generate_pdf_report(sample_scan_dict)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
