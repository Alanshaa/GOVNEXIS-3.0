"""Remediation Tracking Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app.services.remediation_service import RemediationService, ALLOWED_STATUSES

remediation_bp = Blueprint("remediation", __name__)


@remediation_bp.route("/remediation")
def remediation_view():
    """Render Remediation Checklist with lifecycle tracking."""
    host_filter = request.args.get("host", "").strip() or None
    status_filter = request.args.get("status", "All")
    status_val = status_filter if status_filter != "All" else None

    tasks = RemediationService.list_tasks(target_host=host_filter, status_filter=status_val)
    hosts = RemediationService.get_hosts()

    # Summary metrics
    total_tasks = len(tasks)
    open_count = sum(1 for t in tasks if t["status"] == "Open")
    in_prog_count = sum(1 for t in tasks if t["status"] == "In Progress")
    fixed_count = sum(1 for t in tasks if t["status"] == "Fixed")
    verified_count = sum(1 for t in tasks if t["status"] == "Verified")

    return render_template(
        "remediation.html",
        active_page="remediation",
        tasks=tasks,
        hosts=hosts,
        selected_host=host_filter or "All",
        selected_status=status_filter,
        allowed_statuses=ALLOWED_STATUSES,
        total_tasks=total_tasks,
        open_count=open_count,
        in_prog_count=in_prog_count,
        fixed_count=fixed_count,
        verified_count=verified_count,
    )


@remediation_bp.route("/remediation/update", methods=["POST"])
def update_task_view():
    """Update lifecycle status and notes for a remediation task (CSRF protected)."""
    task_id = request.form.get("task_id", type=int)
    new_status = request.form.get("status", "").strip()
    notes = request.form.get("notes", "").strip()

    if not task_id or not new_status:
        flash("Invalid task update parameters.", "danger")
        return redirect(url_for("remediation.remediation_view"))

    try:
        updated = RemediationService.update_task(task_id, new_status, notes)
        if updated:
            flash(f"Task #{task_id} successfully updated to '{new_status}'.", "success")
        else:
            flash(f"Task #{task_id} not found.", "warning")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception as e:
        flash(f"Failed to update task: {str(e)}", "danger")

    return redirect(url_for("remediation.remediation_view"))


@remediation_bp.route("/api/remediation/playbook/<check_id>")
def api_playbook(check_id: str):
    """Retrieve technical hardening snippets for web servers."""
    playbook = RemediationService.get_playbook(check_id)
    if not playbook:
        return jsonify({"error": "Playbook not found"}), 404
    return jsonify(playbook)
