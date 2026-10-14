"""Unit Tests for Defensive Scanner Engine, Timeouts, and Error Handling."""

import pytest
from unittest.mock import patch, MagicMock
import requests

from core.scanner import execute_scan, ScanResult, ScanError
from core.config import LOCAL_DEMO_URL, LOCAL_DEMO_PORT


def test_authorization_enforcement():
    """Scanner must reject scanning if user has not affirmed authorization."""
    with pytest.raises(ScanError) as exc:
        execute_scan("https://example.gov", user_confirmed_authorization=False)
    assert "Authorization confirmation required" in str(exc.value)


@patch("core.scanner.requests.Session.get")
def test_connection_timeout_handling(mock_get):
    """Scanner must convert ConnectTimeout to user-friendly ScanError."""
    mock_get.side_effect = requests.exceptions.ConnectTimeout("Timed out connecting")

    with pytest.raises(ScanError) as exc:
        execute_scan(LOCAL_DEMO_URL, user_confirmed_authorization=True, allow_local_demo=True)
    assert "Connection timed out" in exc.value.message
    assert "remediation_hint" in dir(exc.value)


@patch("core.scanner.requests.Session.get")
def test_read_timeout_handling(mock_get):
    """Scanner must convert ReadTimeout to user-friendly ScanError."""
    mock_get.side_effect = requests.exceptions.ReadTimeout("Timed out reading response")

    with pytest.raises(ScanError) as exc:
        execute_scan(LOCAL_DEMO_URL, user_confirmed_authorization=True, allow_local_demo=True)
    assert "Read timed out" in exc.value.message


@patch("core.scanner.requests.Session.get")
def test_ssl_error_handling(mock_get):
    """Scanner must convert SSLError to user-friendly ScanError."""
    mock_get.side_effect = requests.exceptions.SSLError("Certificate failed verification")

    with pytest.raises(ScanError) as exc:
        execute_scan(LOCAL_DEMO_URL, user_confirmed_authorization=True, allow_local_demo=True)
    assert "TLS/SSL Handshake failed" in exc.value.message
