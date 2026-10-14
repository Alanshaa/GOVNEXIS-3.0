"""Report Generation and Export Routes for GOVNEXIS 3.0."""

import io
from flask import (
    Blueprint, render_template, request, Response, abort, flash, redirect, url_for
)
from app.services.report_service import ReportService
from app.database.db import get_all_scans, get_scan

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
def reports_view():
    """Render Report Generator and in-browser preview page."""
    scans = get_all_scans(limit=100)
    selected_id = request.args.get("scan_id", type=int)

    if not selected_id and scans:
        selected_id = scans[0]["id"]

    scan_dict = None
    json_preview = ""
    csv_preview = ""
    html_preview = ""
    selected_scan_info = None

    if selected_id:
        selected_scan_info = get_scan(selected_id)
        if selected_scan_info:
            scan_dict = ReportService.get_scan_report_data(selected_id)
            if scan_dict:
                json_preview = ReportService.build_json(scan_dict)
                csv_preview = ReportService.build_csv(scan_dict)
                html_preview = ReportService.build_html(scan_dict)

    return render_template(
        "reports.html",
        active_page="reports",
        scans=scans,
        selected_id=selected_id,
        selected_scan_info=selected_scan_info,
        json_preview=json_preview,
        csv_preview=csv_preview,
        html_preview=html_preview,
    )


@reports_bp.route("/reports/download/<format_type>/<int:scan_id>")
def download_report(format_type: str, scan_id: int):
    """Download security configuration audit report in specified format."""
    scan_dict = ReportService.get_scan_report_data(scan_id)
    if not scan_dict:
        flash("Scan record not found.", "danger")
        return redirect(url_for("reports.reports_view"))

    hostname = scan_dict.get("hostname", "host").replace("/", "_").replace(":", "_")
    base_filename = f"GOVNEXIS-Audit-{hostname}"

    fmt = format_type.lower()
    if fmt == "pdf":
        pdf_bytes = ReportService.build_pdf(scan_dict)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={base_filename}.pdf"}
        )
    elif fmt == "html":
        html_content = ReportService.build_html(scan_dict)
        return Response(
            html_content,
            mimetype="text/html; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={base_filename}.html"}
        )
    elif fmt == "json":
        json_content = ReportService.build_json(scan_dict)
        return Response(
            json_content,
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={base_filename}.json"}
        )
    elif fmt == "csv":
        csv_content = ReportService.build_csv(scan_dict)
        return Response(
            csv_content,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={base_filename}.csv"}
        )
    else:
        abort(400, f"Unsupported report format: {format_type}")
