"""Scan History Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.database.db import get_all_scans, get_scans_count, delete_scan, delete_all_scans

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
def history_view():
    """Render SQLite-backed scan history table with search and pagination."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    offset = (page - 1) * per_page
    search_q = request.args.get("q", "").strip() or None

    total_scans = get_scans_count(hostname_filter=search_q)
    total_pages = max(1, (total_scans + per_page - 1) // per_page)

    scans = get_all_scans(limit=per_page, offset=offset, hostname_filter=search_q)

    return render_template(
        "history.html",
        active_page="history",
        scans=scans,
        current_page=page,
        total_pages=total_pages,
        total_scans=total_scans,
        search_query=search_q or "",
    )


@history_bp.route("/history/delete/<int:scan_id>", methods=["POST"])
def delete_scan_view(scan_id: int):
    """Delete a specific audit scan record (CSRF protected)."""
    success = delete_scan(scan_id)
    if success:
        flash(f"Scan record #{scan_id} deleted.", "success")
    else:
        flash(f"Scan record #{scan_id} not found.", "warning")
    return redirect(url_for("history.history_view"))


@history_bp.route("/history/clear", methods=["POST"])
def clear_all_history_view():
    """Clear all audit scans and findings (CSRF protected)."""
    delete_all_scans()
    flash("All audit scan history and remediation tasks cleared.", "info")
    return redirect(url_for("history.history_view"))
