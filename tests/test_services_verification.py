"""Tests for VerificationService and Demo Isolation in GOVNEXIS 3.0."""

import pytest
from app.services.verification_service import VerificationService
from app.database.db import get_all_scans
from core.url_validator import validate_and_resolve_url, SSRFSecurityError, ValidationError


def test_verification_comparison_with_real_records():
    """Verify Before-and-After delta calculations between two stored scans."""
    from app.database.db import save_scan
    from core.scanner import ScanResult
    from core.security_checks import FindingRecord
    from core.scoring import ScoreReport

    scans = get_all_scans(limit=2)
    if len(scans) < 2:
        def make_dummy(score, letter, cvss_s, hsts_status):
            f = FindingRecord(
                check_id="hsts_header",
                title="HSTS Header",
                category="Transport Layer Security",
                status=hsts_status,
                severity="High",
                evidence="HSTS header test",
                why_it_matters="Downgrade protection",
                potential_impact="Interception",
                recommended_action="Enable HSTS"
            )
            rep = ScoreReport(
                final_score=score,
                letter_grade=letter,
                total_possible_points=100,
                earned_points=float(score),
                breakdown=[],
                critical_high_count=1 if hsts_status == "FAIL" else 0,
                summary_statement="Test statement",
                methodology_notes="Test",
                max_cvss_score=cvss_s
            )
            return ScanResult(
                target_url="https://agency-alpha.gov",
                final_url="https://agency-alpha.gov",
                hostname="agency-alpha.gov",
                resolved_ips=["93.184.216.34"],
                status_code=200,
                response_headers={"strict-transport-security": "max-age=31536000"} if hsts_status == "PASS" else {},
                cookies=[],
                tls_info=None,
                findings=[f],
                score_report=rep,
                duration_ms=100,
                timestamp="2026-10-14T10:00:00Z",
                is_demo=False
            )

        save_scan(make_dummy(40, "F", 7.5, "FAIL"))
        save_scan(make_dummy(95, "A", 0.0, "PASS"))
        scans = get_all_scans(limit=2)

    id_a = scans[1]["id"]
    id_b = scans[0]["id"]

    comparison = VerificationService.compare_scans(id_a, id_b)
    assert comparison is not None
    assert "score_delta" in comparison
    assert "cvss_delta" in comparison
    assert "resolved" in comparison
    assert "remaining" in comparison
    assert "regressed" in comparison
    assert "header_diffs" in comparison
    assert isinstance(comparison["resolved_count"], int)
    assert isinstance(comparison["remaining_count"], int)
    assert isinstance(comparison["regressed_count"], int)


def test_verification_nonexistent_scans():
    """Verify comparing non-existent scans returns None."""
    result = VerificationService.compare_scans(999999, 999998)
    assert result is None


def test_demo_isolation_port_enforcement():
    """Verify demo sandbox allowlist strictly enforces port 8765 only."""
    # Localhost on port 8765 with allow_local_demo=True should pass
    clean_url, ips = validate_and_resolve_url("http://127.0.0.1:8765", allow_local_demo=True)
    assert "127.0.0.1" in ips

    # Localhost on another port (e.g. 80, 8080, 22) must be BLOCKED even if allow_local_demo=True
    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_url("http://127.0.0.1:8080", allow_local_demo=True)

    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_url("http://localhost:3000", allow_local_demo=True)

    # Localhost without allow_local_demo=True must ALWAYS be blocked
    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_url("http://127.0.0.1:8765", allow_local_demo=False)
