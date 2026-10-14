"""Unit and Integration Tests for GOVNEXIS 3.0 Flask Application."""

import re
import pytest
from app import create_app
from app.database.db import get_all_scans, init_db


@pytest.fixture
def app():
    """Create application configured for testing."""
    app = create_app("development")
    app.config["TESTING"] = True
    yield app


@pytest.fixture
def client(app):
    """Create Flask test client."""
    return app.test_client()


def test_root_redirects_to_scan(client):
    """Test that GET / redirects to /scan."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/scan" in response.headers.get("Location", "")


@pytest.mark.parametrize("route,title_fragment", [
    ("/scan", "1. New Scan"),
    ("/overview", "2. Overview"),
    ("/findings", "3. Findings"),
    ("/remediation", "4. Remediation"),
    ("/verification", "5. Verification"),
    ("/history", "6. History"),
    ("/reports", "7. Reports"),
    ("/demo-lab", "8. Demo Lab"),
    ("/settings", "9. Settings"),
])
def test_all_nine_navigation_pages_render(client, route, title_fragment):
    """Test that all 9 primary navigation pages return 200 and include brand header & nav order."""
    response = client.get(route, follow_redirects=True)
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "GOVNEXIS" in html
    assert "3.0" in html
    assert title_fragment in html


def test_security_response_headers(client):
    """Verify defensive HTTP security headers are set on all responses."""
    response = client.get("/scan")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin-when-cross-origin" in response.headers.get("Referrer-Policy", "")
    assert "Content-Security-Policy" in response.headers


def test_csrf_protection_on_post(client):
    """Test that POST requests without a valid CSRF token are rejected with 400."""
    response = client.post("/demo-lab/mode", data={"mode": "hardened"})
    assert response.status_code == 400


def test_csrf_protection_with_valid_token(client):
    """Test that POST requests with a valid CSRF token succeed."""
    # Obtain token from GET response
    get_res = client.get("/demo-lab")
    assert get_res.status_code == 200
    html = get_res.data.decode("utf-8")
    match = re.search(r'name=["\']csrf-token["\'] content=["\']([^"\']+)["\']', html)
    assert match is not None
    token = match.group(1)

    post_res = client.post(
        "/demo-lab/mode",
        data={"mode": "hardened", "csrf_token": token},
        follow_redirects=False
    )
    assert post_res.status_code == 302


def test_report_downloads_all_formats(client):
    """Verify report downloads for PDF, HTML, JSON, and CSV."""
    scans = get_all_scans(limit=1)
    if not scans:
        pytest.skip("No scans available for report download test")

    scan_id = scans[0]["id"]

    # PDF
    res_pdf = client.get(f"/reports/download/pdf/{scan_id}")
    assert res_pdf.status_code == 200
    assert res_pdf.mimetype == "application/pdf"
    assert res_pdf.data.startswith(b"%PDF")

    # HTML
    res_html = client.get(f"/reports/download/html/{scan_id}")
    assert res_html.status_code == 200
    assert "text/html" in res_html.mimetype
    assert "GOVNEXIS" in res_html.data.decode("utf-8")

    # JSON
    res_json = client.get(f"/reports/download/json/{scan_id}")
    assert res_json.status_code == 200
    assert res_json.mimetype == "application/json"
    assert "target" in res_json.data.decode("utf-8")

    # CSV
    res_csv = client.get(f"/reports/download/csv/{scan_id}")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.mimetype
    assert "GOVNEXIS" in res_csv.data.decode("utf-8")


def test_404_error_page(client):
    """Verify customized 404 page for missing endpoints."""
    res = client.get("/non-existent-endpoint-404")
    assert res.status_code == 404
    assert "404" in res.data.decode("utf-8")
