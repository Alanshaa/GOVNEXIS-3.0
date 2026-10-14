"""Unit Tests for Transparent Security Scoring Model."""

import pytest
from core.config import (
    CHECK_WEIGHTS, STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)
from core.security_checks import FindingRecord
from core.scoring import compute_security_score, calculate_grade


def test_perfect_score():
    """All passing checks should yield 100/100 and Grade A+."""
    findings = [
        FindingRecord(check_id=cid, title=m["title"], category=m["category"],
                      status=STATUS_PASS, severity=SEV_INFO, evidence="All good",
                      why_it_matters="", potential_impact="", recommended_action="")
        for cid, m in CHECK_WEIGHTS.items()
    ]
    report = compute_security_score(findings)
    assert report.final_score == 100
    assert report.letter_grade in ("A+", "A")
    assert report.critical_high_count == 0


def test_zero_score():
    """All failing checks should yield 0/100 and Grade F."""
    findings = [
        FindingRecord(check_id=cid, title=m["title"], category=m["category"],
                      status=STATUS_FAIL, severity=m["severity_on_fail"], evidence="Failed",
                      why_it_matters="", potential_impact="", recommended_action="")
        for cid, m in CHECK_WEIGHTS.items()
    ]
    report = compute_security_score(findings)
    assert report.final_score == 0
    assert report.letter_grade == "F"
    assert report.critical_high_count > 0


def test_partial_credit_warnings():
    """Warning status must award exactly 50% partial credit."""
    # Create 1 warning check with weight 20 and others pass
    findings = []
    for cid, m in CHECK_WEIGHTS.items():
        if cid == "https_enforced":
            st = STATUS_WARNING  # weight 20 -> should earn 10 pts
        else:
            st = STATUS_PASS
        findings.append(FindingRecord(
            check_id=cid, title=m["title"], category=m["category"],
            status=st, severity=SEV_MEDIUM, evidence="Ev",
            why_it_matters="", potential_impact="", recommended_action=""
        ))

    report = compute_security_score(findings)
    # Total possible is 100, earned is 10 + 80 = 90
    assert report.final_score == 90
    assert report.letter_grade in ("A", "A-", "B+")


def test_not_assessed_exclusion():
    """Checks marked NOT ASSESSED must be excluded from scoring denominator."""
    # Exclude HSTS (weight 15) and TLS (weight 5)
    findings = []
    for cid, m in CHECK_WEIGHTS.items():
        if cid in ("hsts_header", "tls_configuration"):
            st = STATUS_NOT_ASSESSED
        else:
            st = STATUS_PASS
        findings.append(FindingRecord(
            check_id=cid, title=m["title"], category=m["category"],
            status=st, severity=SEV_INFO, evidence="Ev",
            why_it_matters="", potential_impact="", recommended_action=""
        ))

    report = compute_security_score(findings)
    # Total assessed possible is 100 - 20 = 80
    # Earned is 80 -> Normalized is 100
    assert report.total_possible_points == 80
    assert report.final_score == 100
