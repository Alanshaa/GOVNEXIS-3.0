"""Scanner Routes for GOVNEXIS 3.0."""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app.services.scanner_service import ScannerService
from app.database.db import get_scan
from core.scanner import ScanError
from core.url_validator import ValidationError, SSRFSecurityError
from config import LOCAL_DEMO_URL

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scan", methods=["GET", "POST"])
def scanner_view():
    """Render New Scan page and process form audit submissions."""
    active_scan = None
    scan_id = request.args.get("scan_id", type=int)

    if scan_id:
        active_scan = get_scan(scan_id)

    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        auth_confirmed = bool(request.form.get("auth_confirmed"))

        if not target_url:
            flash("Please enter a valid website URL or IP destination to audit.", "danger")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)

        if not auth_confirmed:
            flash("Audit halted: You must certify that you are authorized to audit this endpoint.", "danger")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)

        try:
            scan_result, saved_id = ScannerService.run_scan(
                target_url=target_url,
                user_confirmed_authorization=True,
                save_to_db=True
            )
            flash(f"Security configuration audit completed successfully. Record #{saved_id} saved.", "success")
            return redirect(url_for("scanner.scanner_view", scan_id=saved_id))

        except SSRFSecurityError as e:
            flash(f"Security Policy Block (SSRF Prevention): {str(e)}", "danger")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)
        except ValidationError as e:
            flash(f"Target Validation Error: {str(e)}", "warning")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)
        except ScanError as e:
            msg = f"Audit Scan Error: {e.message}"
            if e.technical_details:
                msg += f" — Details: {e.technical_details}"
            flash(msg, "danger")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)
        except Exception as e:
            flash(f"Unexpected scanning failure: {str(e)}", "danger")
            return render_template("scanner.html", active_page="new_scan", target_url=target_url, local_demo_url=LOCAL_DEMO_URL)

    return render_template(
        "scanner.html",
        active_page="new_scan",
        active_scan=active_scan,
        local_demo_url=LOCAL_DEMO_URL,
    )


@scanner_bp.route("/api/scan", methods=["POST"])
def api_scan():
    """AJAX endpoint for executing scans asynchronously from modern UI."""
    data = request.get_json() or {}
    target_url = data.get("target_url", "").strip()
    auth_confirmed = bool(data.get("auth_confirmed"))

    if not target_url:
        return jsonify({"success": False, "error": "URL cannot be empty."}), 400

    if not auth_confirmed:
        return jsonify({"success": False, "error": "Authorization confirmation is required."}), 400

    try:
        scan_result, saved_id = ScannerService.run_scan(
            target_url=target_url,
            user_confirmed_authorization=True,
            save_to_db=True
        )
        return jsonify({
            "success": True,
            "scan_id": saved_id,
            "redirect_url": url_for("scanner.scanner_view", scan_id=saved_id),
            "result": scan_result.to_dict()
        })
    except SSRFSecurityError as e:
        return jsonify({"success": False, "error": f"SSRF Security Violation: {str(e)}"}), 403
    except ValidationError as e:
        return jsonify({"success": False, "error": f"Validation Error: {str(e)}"}), 400
    except ScanError as e:
        return jsonify({
            "success": False,
            "error": e.message,
            "details": e.technical_details,
            "hint": e.remediation_hint
        }), 422
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal scan error: {str(e)}"}), 500
