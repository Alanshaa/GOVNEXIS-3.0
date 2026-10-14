"""Before-and-After Verification Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request
from app.services.verification_service import VerificationService
from app.database.db import get_all_scans

verification_bp = Blueprint("verification", __name__)


@verification_bp.route("/verification")
def verification_view():
    """Render Empirical Before-and-After Verification UI."""
    scans = get_all_scans(limit=100)
    baseline_id = request.args.get("baseline_id", type=int)
    rescan_id = request.args.get("rescan_id", type=int)

    comparison = None
    if baseline_id and rescan_id:
        if baseline_id == rescan_id:
            comparison = {"error": "Please select two distinct scans to evaluate verification deltas."}
        else:
            comparison = VerificationService.compare_scans(baseline_id, rescan_id)
            if not comparison:
                comparison = {"error": "Selected scans could not be found or loaded."}

    return render_template(
        "verification.html",
        active_page="verification",
        scans=scans,
        baseline_id=baseline_id,
        rescan_id=rescan_id,
        comparison=comparison,
    )
