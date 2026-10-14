"""Main and Overview Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, redirect, url_for, request, jsonify
from app.database.db import get_scan_trends, get_all_scans
from config import APP_NAME, APP_VERSION, APP_TAGLINE

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Default route: redirects to the New Scan page as requested by navigation hierarchy."""
    return redirect(url_for("scanner.scanner_view"))


@main_bp.route("/overview")
def overview():
    """Executive cybersecurity operations overview and trends dashboard."""
    trends = get_scan_trends()
    recent_scans = get_all_scans(limit=10)

    return render_template(
        "dashboard.html",
        active_page="overview",
        trends=trends,
        recent_scans=recent_scans,
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_tagline=APP_TAGLINE,
    )


@main_bp.route("/api/trends")
def api_trends():
    """JSON API for real-time dashboard chart updates."""
    trends = get_scan_trends()
    return jsonify(trends)
