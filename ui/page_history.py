"""Scan History and Historical Trends for GOVNEXIS.

Enables:
- Auditing chronological scan records
- Filtering and searching by target and date
- Re-opening complete past scan results
- Deleting individual or all historical records
- Exporting full scan history
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any, List

from core.database import get_all_scans, get_scan, delete_scan, delete_all_scans
from ui.theme import render_page_header, get_tokens


def render_history_page() -> None:
    """Render the persistent scan history and management interface."""
    render_page_header(
        "History",
        "Audit chronological scan records, inspect past findings, and manage scan logs",
    )
    tokens = get_tokens()

    scans = get_all_scans(limit=100)

    if not scans:
        st.info("No historical scan records found. Run scans on the New Scan page or use the Demo Lab.")
        return

    # Filter Toolbar
    c_search, c_filter, c_del = st.columns([2, 1.5, 1])

    with c_search:
        search_host = st.text_input("Search Hostname", placeholder="Filter by host...")

    with c_filter:
        hostnames = ["All Targets"] + sorted(list(set(s["hostname"] for s in scans)))
        selected_target = st.selectbox("Target Host", hostnames)

    with c_del:
        st.write("")
        if st.button("Clear All History", type="secondary", use_container_width=True):
            delete_all_scans()
            st.success("All historical scan records cleared.")
            st.rerun()

    # Filtering
    filtered_scans = scans
    if search_host.strip():
        filtered_scans = [s for s in filtered_scans if search_host.lower() in s["hostname"].lower()]
    if selected_target != "All Targets":
        filtered_scans = [s for s in filtered_scans if s["hostname"] == selected_target]

    st.markdown(f"<span style='font-size: 0.85rem; color: {tokens['text_muted']};'>Found {len(filtered_scans)} historical audit records</span>", unsafe_allow_html=True)
    st.write("")

    # Display Scan Table
    table_rows = []
    for s in filtered_scans:
        max_cvss_val = s.get("max_cvss", 0.0)
        cvss_sev = s.get("cvss_severity", "None").upper()

        table_rows.append({
            "Scan ID": s["id"],
            "Target Host": s["hostname"],
            "Timestamp": s["timestamp"][:19],
            "CVSS v3.0 Base Score": f"{max_cvss_val:.1f}",
            "CVSS Severity": cvss_sev,
            "Passed": s["passed_checks"],
            "Failed": s["failed_checks"],
            "Warnings": s["warning_checks"],
            "Type": "Local Demo" if s["is_demo"] else "External",
        })

    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    # Detailed Inspection Selector
    st.write("")
    st.subheader("Inspect Scan Record")
    col_pick, col_act = st.columns([3, 1])

    with col_pick:
        scan_id_options = {s["id"]: f"Scan #{s['id']} — {s['hostname']} (CVSS {s.get('max_cvss', 0.0):.1f}, {s['timestamp'][:16]})" for s in filtered_scans}
        picked_id = st.selectbox("Select Scan to Inspect", list(scan_id_options.keys()), format_func=lambda x: scan_id_options[x], label_visibility="collapsed")

    with col_act:
        if st.button("Delete Selected", key="btn_del_single", use_container_width=True):
            delete_scan(picked_id)
            st.success(f"Scan #{picked_id} deleted.")
            st.rerun()

    # Show details of selected scan
    selected_scan_detail = get_scan(picked_id)
    if selected_scan_detail:
        det_cvss = selected_scan_detail.get("max_cvss", 0.0)
        det_sev = selected_scan_detail.get("cvss_severity", "None").upper()
        with st.expander(f"Full Details for Scan #{picked_id} ({selected_scan_detail['hostname']})", expanded=True):
            c_info1, c_info2 = st.columns(2)
            with c_info1:
                st.markdown(f"**Target URL:** `{selected_scan_detail['target_url']}`")
                st.markdown(f"**Final Destination:** `{selected_scan_detail['final_url']}`")
                st.markdown(f"**HTTP Status:** `{selected_scan_detail['status_code']}`")
            with c_info2:
                st.markdown(f"**CVSS v3.0 Base Score:** `{det_cvss:.1f} ({det_sev})`")
                st.markdown(f"**Scan Duration:** `{selected_scan_detail['duration_ms']} ms`")
                st.markdown(f"**Timestamp:** `{selected_scan_detail['timestamp']}`")

            st.markdown("#### Findings in this Scan")
            findings_data = []
            for f in selected_scan_detail.get("findings", []):
                cvss_sc = f.get("cvss_score")
                cvss_st = f.get("cvss_status") or ("NOT_SCORED" if cvss_sc is None else "SCORED")
                cvss_display = f"{cvss_sc:.1f} ({f.get('cvss_severity')})" if cvss_st == "SCORED" and cvss_sc is not None else "Not Scored"
                vec_or_reason = f.get("cvss_vector") or f.get("cvss_unscored_reason") or "Defense-in-depth"
                findings_data.append({
                    "Check": f["title"],
                    "Status": f["status"],
                    "CVSS v3.0": cvss_display,
                    "CVSS Vector / Rationale": vec_or_reason,
                    "Evidence": f["evidence"][:60],
                    "Action": f["recommended_action"][:60],
                })
            st.dataframe(pd.DataFrame(findings_data), use_container_width=True, hide_index=True)
