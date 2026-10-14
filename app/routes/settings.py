"""Settings and Standards Reference Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from config import (
    APP_NAME, APP_VERSION, APP_TAGLINE, APP_DESCRIPTION, APP_CATEGORY, AUTHOR,
    CHECK_WEIGHTS, CONNECT_TIMEOUT, READ_TIMEOUT, MAX_REDIRECTS, MAX_RESPONSE_BYTES,
    SCAN_USER_AGENT, LOCAL_DEMO_URL, DATABASE_PATH
)
from app.database.db import seed_demo_history, get_scan_trends

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
def settings_view():
    """Render Settings, Methodology, Standards Mapping and Guided Help."""
    trends = get_scan_trends()

    # Build standards reference table using official FIRST CVSS v3.0 metrics
    from core.cvss import assign_finding_cvss
    standards = []
    for cid, meta in CHECK_WEIGHTS.items():
        sample_cvss = assign_finding_cvss(cid, "FAIL")
        standards.append({
            "check_id": cid,
            "title": meta["title"],
            "cvss_score": sample_cvss.base_score,
            "cvss_severity": sample_cvss.severity,
            "cvss_vector": sample_cvss.vector_string,
            "severity": meta["severity_on_fail"],
            "category": meta["category"],
            "description": meta["description"],
            "standard": meta.get("standard_reference", "CISA BOD 18-01 / OWASP"),
            "nature": f"CVSS v3.0 {sample_cvss.severity}" if sample_cvss.base_score else "Defense-in-Depth Hygiene",
        })

    return render_template(
        "settings.html",
        active_page="settings",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_tagline=APP_TAGLINE,
        app_description=APP_DESCRIPTION,
        app_category=APP_CATEGORY,
        author=AUTHOR,
        standards=standards,
        connect_timeout=CONNECT_TIMEOUT,
        read_timeout=READ_TIMEOUT,
        max_redirects=MAX_REDIRECTS,
        max_response_bytes=MAX_RESPONSE_BYTES,
        scan_user_agent=SCAN_USER_AGENT,
        local_demo_url=LOCAL_DEMO_URL,
        database_path=DATABASE_PATH,
        trends=trends,
    )


@settings_bp.route("/settings/seed", methods=["POST"])
def seed_database():
    """Seed sample audit records for demonstration (CSRF protected)."""
    seed_demo_history()
    flash("Sample demonstration audit records successfully verified in database.", "success")
    return redirect(url_for("settings.settings_view"))
