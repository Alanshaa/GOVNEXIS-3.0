"""Unit Tests for Local Demo Lab and Before-and-After Verification Workflow."""

import time
import pytest
import requests

from core.config import LOCAL_DEMO_URL, LOCAL_DEMO_PORT, LOCAL_DEMO_HOST
from core.mock_site import (
    start_mock_server, stop_mock_server, get_demo_status,
    DEMO_STATE, MockServerState
)
from core.scanner import execute_scan


@pytest.fixture(scope="module", autouse=True)
def setup_mock_server():
    """Ensure mock server is running for tests in this module."""
    started = start_mock_server()
    assert started is True
    time.sleep(0.2)
    yield
    stop_mock_server()


def test_mock_server_status():
    """Verify demo status retrieval."""
    status = get_demo_status()
    assert status["running"] is True
    assert status["port"] == LOCAL_DEMO_PORT


def test_baseline_vs_hardened_responses():
    """Verify that toggling DEMO_STATE alters HTTP response headers."""
    # Test Baseline State
    DEMO_STATE.set_mode(MockServerState.MODE_BASELINE)
    resp_baseline = requests.get(LOCAL_DEMO_URL, timeout=3)
    assert resp_baseline.status_code == 200
    assert "Strict-Transport-Security" not in resp_baseline.headers
    assert "Content-Security-Policy" not in resp_baseline.headers
    assert "Apache" in resp_baseline.headers.get("Server", "")
    assert "PHP" in resp_baseline.headers.get("X-Powered-By", "")

    # Test Hardened State
    DEMO_STATE.set_mode(MockServerState.MODE_HARDENED)
    resp_hardened = requests.get(LOCAL_DEMO_URL, timeout=3)
    assert resp_hardened.status_code == 200
    assert "Strict-Transport-Security" in resp_hardened.headers
    assert "Content-Security-Policy" in resp_hardened.headers
    assert resp_hardened.headers.get("X-Frame-Options") == "DENY"
    assert resp_hardened.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp_hardened.headers.get("Server") == "GOVNEXIS-SecureGateway"


def test_end_to_end_audit_verification_delta():
    """Run real scans against baseline and hardened states and verify score delta."""
    # 1. Baseline Scan
    DEMO_STATE.set_mode(MockServerState.MODE_BASELINE)
    res_baseline = execute_scan(
        target_url=LOCAL_DEMO_URL,
        user_confirmed_authorization=True,
        allow_local_demo=True
    )
    baseline_score = res_baseline.score_report.final_score

    # 2. Hardened Scan
    DEMO_STATE.set_mode(MockServerState.MODE_HARDENED)
    res_hardened = execute_scan(
        target_url=LOCAL_DEMO_URL,
        user_confirmed_authorization=True,
        allow_local_demo=True
    )
    hardened_score = res_hardened.score_report.final_score

    # Hardened score must be significantly higher than baseline
    assert hardened_score > baseline_score
    score_delta = hardened_score - baseline_score
    assert score_delta >= 40  # Meaningful jump in score!
