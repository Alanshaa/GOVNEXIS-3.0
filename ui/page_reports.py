"""Professional Report Generator Page for GOVNEXIS.

Supports multi-format report exports:
- Executive PDF (Vector printable report)
- Standalone HTML (With print-ready styling)
- Structured JSON (Machine-readable)
- CSV Spreadsheet (Issue tracker ingestion)
- Live interactive HTML preview
"""

import streamlit as st
import streamlit.components.v1 as components
from typing import Dict, Any

from core.database import get_all_scans, get_scan
from core.reports import generate_json_report, generate_html_report, generate_csv_report, generate_pdf_report
from ui.theme import render_page_header, get_tokens


def render_reports_page() -> None:
    """Render the Report Generator page."""
    render_page_header(
        "Reports",
        "Generate and export compliance reports in PDF, HTML, JSON, and CSV formats",
    )
    tokens = get_tokens()

    scans = get_all_scans(limit=50)
    if not scans:
        st.info("No scan records found to generate reports for. Please run an audit scan first.")
        return

    # Select target scan
    scan_options = {s["id"]: f"#{s['id']} — {s['hostname']} (CVSS v3.0: {s.get('max_cvss', 0.0):.1f} {s.get('cvss_severity', 'None')}, {s['timestamp'][:16]})" for s in scans}
    chosen_id = st.selectbox("Select Scan to Export", list(scan_options.keys()), format_func=lambda x: scan_options[x])

    scan_data = get_scan(chosen_id)
    if not scan_data:
        st.error("Unable to load selected scan data.")
        return

    # Generate documents
    scan_dict = scan_data.get("details", {})
    if "findings" not in scan_dict:
        scan_dict["findings"] = scan_data.get("findings", [])

    pdf_bytes = generate_pdf_report(scan_dict)
    html_str = generate_html_report(scan_dict)
    json_str = generate_json_report(scan_dict)
    csv_str = generate_csv_report(scan_dict)

    hostname = scan_data["hostname"]

    # Export Buttons
    st.write("")
    st.subheader("Download Reports")
    c_pdf, c_html, c_json, c_csv = st.columns(4)

    with c_pdf:
        st.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"GOVNEXIS-Audit-{hostname}.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True
        )

    with c_html:
        st.download_button(
            "Download HTML",
            data=html_str,
            file_name=f"GOVNEXIS-Audit-{hostname}.html",
            mime="text/html",
            use_container_width=True
        )

    with c_json:
        st.download_button(
            "Download JSON",
            data=json_str,
            file_name=f"GOVNEXIS-Audit-{hostname}.json",
            mime="application/json",
            use_container_width=True
        )

    with c_csv:
        st.download_button(
            "Download CSV",
            data=csv_str,
            file_name=f"GOVNEXIS-Audit-{hostname}.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.write("")

    # Live In-Browser Preview
    st.subheader("Report Preview")
    tab_html_preview, tab_json_preview, tab_csv_preview = st.tabs(["HTML Preview", "JSON Preview", "CSV Preview"])

    with tab_html_preview:
        components.html(html_str, height=700, scrolling=True)

    with tab_json_preview:
        st.code(json_str, language="json")

    with tab_csv_preview:
        st.code(csv_str, language="csv")
