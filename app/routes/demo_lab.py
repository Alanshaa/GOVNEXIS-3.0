"""Local Demo Lab Sandbox Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from core.mock_site import (
    start_mock_server, get_demo_status, DEMO_STATE, MockServerState
)
from app.services.scanner_service import ScannerService
from app.services.verification_service import VerificationService
from app.database.db import get_all_scans
from config import LOCAL_DEMO_URL

demo_lab_bp = Blueprint("demo_lab", __name__)


@demo_lab_bp.route("/demo-lab")
def demo_lab_view():
    """Render Isolated Local Demo Lab sandbox control page."""
    start_mock_server()
    status = get_demo_status()

    # Find recent demo scans for live comparison
    all_demo_scans = [s for s in get_all_scans(limit=20) if s.get("is_demo") or s.get("hostname") == "127.0.0.1"]
    latest_scan = all_demo_scans[0] if all_demo_scans else None

    # Check if we have two demo scans to show quick before-and-after
    comparison = None
    if len(all_demo_scans) >= 2:
        # Comparison between second latest and latest
        comparison = VerificationService.compare_scans(all_demo_scans[1]["id"], all_demo_scans[0]["id"])

    return render_template(
        "demo_lab.html",
        active_page="demo_lab",
        status=status,
        latest_scan=latest_scan,
        all_demo_scans=all_demo_scans,
        comparison=comparison,
        local_demo_url=LOCAL_DEMO_URL,
    )


@demo_lab_bp.route("/demo-lab/mode", methods=["POST"])
def toggle_mode():
    """Toggle simulated security posture between Baseline and Hardened (CSRF protected)."""
    target_mode = request.form.get("mode")
    if target_mode in (MockServerState.MODE_BASELINE, MockServerState.MODE_HARDENED):
        DEMO_STATE.set_mode(target_mode)
        label = "HARDENED (Compliant)" if target_mode == MockServerState.MODE_HARDENED else "BASELINE (Misconfigured)"
        flash(f"Sandbox posture updated to: {label}", "info")
    return redirect(url_for("demo_lab.demo_lab_view"))


@demo_lab_bp.route("/demo-lab/scan", methods=["POST"])
def run_demo_scan():
    """Execute scan against the isolated local sandbox (CSRF protected)."""
    start_mock_server()
    mode = request.form.get("mode")
    if mode in (MockServerState.MODE_BASELINE, MockServerState.MODE_HARDENED):
        DEMO_STATE.set_mode(mode)

    try:
        scan_res, scan_id = ScannerService.run_scan(
            target_url=LOCAL_DEMO_URL,
            user_confirmed_authorization=True,
            allow_local_demo=True,
            save_to_db=True
        )
        mode_label = DEMO_STATE.get_mode().upper()
        flash(f"Sandbox {mode_label} scan completed. Score: {scan_res.score_report.final_score}/100 (Grade {scan_res.score_report.letter_grade}).", "success")
        return redirect(url_for("demo_lab.demo_lab_view"))
    except Exception as e:
        flash(f"Sandbox scan failure: {str(e)}", "danger")
        return redirect(url_for("demo_lab.demo_lab_view"))
