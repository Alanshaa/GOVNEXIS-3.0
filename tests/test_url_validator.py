"""Unit Tests for URL and Network Safety Validator."""

import pytest
from core.url_validator import (
    validate_and_resolve_url,
    validate_redirect_target,
    is_ip_prohibited,
    ValidationError,
    SSRFSecurityError
)
from core.config import LOCAL_DEMO_URL, LOCAL_DEMO_PORT


def test_empty_and_invalid_urls():
    """Ensure empty or malformed inputs raise ValidationError."""
    with pytest.raises(ValidationError):
        validate_and_resolve_url("")
    with pytest.raises(ValidationError):
        validate_and_resolve_url("   ")


def test_unsupported_schemes():
    """Ensure non-HTTP/HTTPS schemes are strictly rejected."""
    with pytest.raises(ValidationError) as exc:
        validate_and_resolve_url("ftp://example.gov")
    assert "Unsupported protocol scheme" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        validate_and_resolve_url("file:///etc/passwd")
    assert "Unsupported protocol scheme" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        validate_and_resolve_url("gopher://old.gov")
    assert "Unsupported protocol scheme" in str(exc.value)


def test_ip_prohibitions():
    """Verify classification of loopback, private, link-local, and multicast IPs."""
    # Loopback
    prohibited, reason = is_ip_prohibited("127.0.0.1")
    assert prohibited is True
    assert "Loopback" in reason

    prohibited, reason = is_ip_prohibited("::1")
    assert prohibited is True

    # Private RFC 1918
    prohibited, _ = is_ip_prohibited("10.10.10.10")
    assert prohibited is True

    prohibited, _ = is_ip_prohibited("192.168.1.50")
    assert prohibited is True

    prohibited, _ = is_ip_prohibited("172.16.0.5")
    assert prohibited is True

    # Link-local & Multicast
    prohibited, _ = is_ip_prohibited("169.254.169.254")
    assert prohibited is True

    prohibited, _ = is_ip_prohibited("224.0.0.1")
    assert prohibited is True

    # Public Routable IP
    prohibited, _ = is_ip_prohibited("8.8.8.8")
    assert prohibited is False


def test_loopback_blocked_in_external_mode():
    """Targeting localhost without allow_local_demo must raise SSRFSecurityError."""
    with pytest.raises(SSRFSecurityError) as exc:
        validate_and_resolve_url("http://127.0.0.1:8080", allow_local_demo=False)
    assert "Loopback targets" in str(exc.value)

    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_url("http://localhost:3000", allow_local_demo=False)


def test_local_demo_allowlist_on_designated_port():
    """Local demo target on port 8765 must be accepted when allow_local_demo=True."""
    url, ips = validate_and_resolve_url(LOCAL_DEMO_URL, allow_local_demo=True)
    assert "127.0.0.1" in url or "localhost" in url
    assert ips == ["127.0.0.1"]


def test_local_demo_rejected_on_wrong_port():
    """Local demo must still be rejected if an attacker tries targeting other ports."""
    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_url("http://127.0.0.1:22", allow_local_demo=True)


def test_redirect_validation():
    """Verify safe handling and resolution of redirect URLs."""
    base = LOCAL_DEMO_URL + "/portal"
    relative = "/login"
    # Relative redirect resolving
    target = validate_redirect_target(base, relative, allow_local_demo=True)
    assert target == LOCAL_DEMO_URL + "/login"

    # Reject redirecting to private SSRF destination
    with pytest.raises(SSRFSecurityError):
        validate_redirect_target(base, "http://10.0.0.1/admin", allow_local_demo=True)
