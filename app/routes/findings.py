"""Findings Explorer Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request
from app.database.db import search_findings, get_all_scans
from config import CHECK_WEIGHTS

findings_bp = Blueprint("findings", __name__)


@findings_bp.route("/findings")
def findings_view():
    """Render Findings Center with multi-parameter filtering and search."""
    query = request.args.get("q", "").strip()
    severity = request.args.get("severity", "All")
    category = request.args.get("category", "All")
    status = request.args.get("status", "All")
    scan_id = request.args.get("scan_id", type=int)

    findings = search_findings(
        query=query if query else None,
        severity=severity if severity != "All" else None,
        category=category if category != "All" else None,
        status=status if status != "All" else None,
        scan_id=scan_id,
        limit=250
    )

    # Categories list for filter dropdown
    categories = sorted(list({meta["category"] for meta in CHECK_WEIGHTS.values()}))
    scans = get_all_scans(limit=50)

    # Calculate summary metrics for current filtered set
    total_found = len(findings)
    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    warn_count = sum(1 for f in findings if f["status"] == "WARNING")
    pass_count = sum(1 for f in findings if f["status"] == "PASS")

    return render_template(
        "findings.html",
        active_page="findings",
        findings=findings,
        query=query,
        selected_severity=severity,
        selected_category=category,
        selected_status=status,
        selected_scan_id=scan_id,
        categories=categories,
        scans=scans,
        total_found=total_found,
        fail_count=fail_count,
        warn_count=warn_count,
        pass_count=pass_count,
    )
