"""Unit Tests for Security Configuration Auditing Rules."""

import pytest
from core.config import (
    STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)
from core.security_checks import (
    audit_https_enforcement,
    audit_hsts,
    audit_content_security_policy,
    audit_x_frame_options,
    audit_x_content_type_options,
    audit_cookies,
    audit_referrer_policy,
    audit_permissions_policy,
    audit_server_disclosure,
    audit_tls_configuration,
)


def test_https_enforcement():
    """Verify HTTPS enforcement and HTTP fallback detection."""
    # HTTPS pass
    res_pass = audit_https_enforcement("https://agency.gov", "http://agency.gov", True, 200)
    assert res_pass.status == STATUS_PASS
    assert res_pass.check_id == "https_enforced"

    # Plaintext HTTP fail
    res_fail = audit_https_enforcement("http://agency.gov", "http://agency.gov", False, 200)
    assert res_fail.status == STATUS_FAIL
    assert res_fail.severity == SEV_CRITICAL


def test_hsts_audit():
    """Verify HSTS check across various header states."""
    # Not assessed on HTTP
    res_na = audit_hsts({}, is_https=False)
    assert res_na.status == STATUS_NOT_ASSESSED

    # Missing header on HTTPS -> FAIL
    res_missing = audit_hsts({}, is_https=True)
    assert res_missing.status == STATUS_FAIL
    assert res_missing.severity == SEV_HIGH

    # Short max-age -> FAIL
    res_short = audit_hsts({"strict-transport-security": "max-age=3600"}, is_https=True)
    assert res_short.status == STATUS_FAIL

    # 18 weeks -> WARNING
    res_warn = audit_hsts({"strict-transport-security": "max-age=11000000"}, is_https=True)
    assert res_warn.status == STATUS_WARNING

    # 1 year optimal -> PASS
    res_opt = audit_hsts({"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}, is_https=True)
    assert res_opt.status == STATUS_PASS


def test_content_security_policy():
    """Verify CSP header auditing."""
    # Absent -> FAIL
    res_none = audit_content_security_policy({})
    assert res_none.status == STATUS_FAIL
    assert res_none.severity == SEV_HIGH

    # Unsafe inline -> WARNING
    res_unsafe = audit_content_security_policy({
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
    })
    assert res_unsafe.status == STATUS_WARNING
    assert res_unsafe.severity == SEV_MEDIUM

    # Restrictive policy -> PASS
    res_good = audit_content_security_policy({
        "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'"
    })
    assert res_good.status == STATUS_PASS


def test_clickjacking_defense():
    """Verify X-Frame-Options and CSP frame-ancestors checks."""
    # Missing both -> FAIL
    res_fail = audit_x_frame_options({})
    assert res_fail.status == STATUS_FAIL

    # X-Frame-Options DENY -> PASS
    res_xfo = audit_x_frame_options({"x-frame-options": "DENY"})
    assert res_xfo.status == STATUS_PASS

    # CSP frame-ancestors 'none' -> PASS
    res_csp = audit_x_frame_options({"content-security-policy": "default-src 'self'; frame-ancestors 'none'"})
    assert res_csp.status == STATUS_PASS


def test_x_content_type_options():
    """Verify MIME-sniffing protection."""
    # Missing -> FAIL
    res_fail = audit_x_content_type_options({})
    assert res_fail.status == STATUS_FAIL

    # nosniff -> PASS
    res_pass = audit_x_content_type_options({"x-content-type-options": "nosniff"})
    assert res_pass.status == STATUS_PASS


def test_cookie_security():
    """Verify cookie flag auditing."""
    # Stateless -> PASS
    res_stateless = audit_cookies([], is_https=True)
    assert res_stateless.status == STATUS_PASS

    # Missing HttpOnly and Secure on HTTPS -> FAIL
    bad_cookies = ["session_id=abc12345; Path=/"]
    res_bad = audit_cookies(bad_cookies, is_https=True)
    assert res_bad.status == STATUS_FAIL
    assert "Secure flag missing" in res_bad.evidence

    # Hardened cookies -> PASS
    good_cookies = ["session_id=abc12345; Secure; HttpOnly; SameSite=Lax; Path=/"]
    res_good = audit_cookies(good_cookies, is_https=True)
    assert res_good.status == STATUS_PASS


def test_referrer_and_permissions_policy():
    """Verify Referrer-Policy and Permissions-Policy rules."""
    # Referrer absent -> WARNING
    res_ref_warn = audit_referrer_policy({})
    assert res_ref_warn.status == STATUS_WARNING

    # Strict Referrer -> PASS
    res_ref_pass = audit_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})
    assert res_ref_pass.status == STATUS_PASS

    # Permissions-Policy absent -> WARNING
    res_perm_warn = audit_permissions_policy({})
    assert res_perm_warn.status == STATUS_WARNING

    # Permissions-Policy set -> PASS
    res_perm_pass = audit_permissions_policy({"permissions-policy": "camera=(), microphone=()"})
    assert res_perm_pass.status == STATUS_PASS


def test_server_disclosure():
    """Verify detection of verbose server and framework banners."""
    # Verbose Apache banner -> FAIL
    res_leak = audit_server_disclosure({
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3"
    })
    assert res_leak.status == STATUS_FAIL

    # Suppressed / Generic banner -> PASS
    res_clean = audit_server_disclosure({"server": "CloudFront"})
    assert res_clean.status == STATUS_PASS


def test_tls_configuration():
    """Verify TLS protocol version and certificate expiry checks."""
    # Plaintext HTTP -> NOT ASSESSED
    res_na = audit_tls_configuration(None, is_https=False)
    assert res_na.status == STATUS_NOT_ASSESSED

    # Deprecated TLS 1.0 -> FAIL
    tls_deprecated = {
        "protocol": "TLSv1",
        "days_until_expiry": 100,
        "subject_common_name": "test.gov",
        "issuer_common_name": "CA",
        "cipher": "DES-CBC3-SHA"
    }
    res_dep = audit_tls_configuration(tls_deprecated, is_https=True)
    assert res_dep.status == STATUS_FAIL

    # Expired cert -> FAIL
    tls_expired = {
        "protocol": "TLSv1.3",
        "days_until_expiry": -5,
        "subject_common_name": "test.gov",
        "issuer_common_name": "CA",
        "cipher": "TLS_AES_256_GCM_SHA384"
    }
    res_exp = audit_tls_configuration(tls_expired, is_https=True)
    assert res_exp.status == STATUS_FAIL
    assert res_exp.severity == SEV_CRITICAL

    # Valid TLS 1.3 cert -> PASS
    tls_valid = {
        "protocol": "TLSv1.3",
        "days_until_expiry": 180,
        "subject_common_name": "portal.gov",
        "issuer_common_name": "DigiCert",
        "cipher": "TLS_AES_256_GCM_SHA384"
    }
    res_ok = audit_tls_configuration(tls_valid, is_https=True)
    assert res_ok.status == STATUS_PASS
