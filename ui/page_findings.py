"""Findings page for GOVNEXIS.

Provides:
- Search, multi-dimensional filtering, and rule-based prioritization
- Vulnerability details with evidence, risk explanation, and remediation guidance
- Verification lifecycle tracking (Open, In Progress, Fixed, Verified)
"""

import streamlit as st
from typing import List, Dict, Any

from core.database import get_connection
from ui.theme import (
    render_page_header,
    render_info_banner,
    get_status_badge_html,
    get_severity_badge_html,
    render_safe_html,
    get_tokens,
    get_verification_color,
)


def render_findings_page() -> None:
    """Render the Security Findings and Priority Center."""
    render_page_header(
        "Findings",
        "Search, filter, and track security findings across all audited targets",
    )
    tokens = get_tokens()

    # Fetch all findings joined with scans
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.*, s.hostname, s.timestamp as scan_time, s.target_url
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            ORDER BY 
                f.cvss_score DESC NULLS LAST,
                CASE f.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END ASC,
                f.id DESC
        """)
        rows = cursor.fetchall()
        all_findings = [dict(r) for r in rows]

    if not all_findings:
        st.info("No findings found in the database. Run a scan from the New Scan page or audit a target to populate results.")
        return

    # Prioritization Methodology Notice
    render_safe_html(f"""
    <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-left: 4px solid {tokens['accent']}; padding: 14px 18px; border-radius: 6px; margin-bottom: 20px;">
        <div style="font-weight: 600; color: {tokens['accent']}; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.04em;">Official CVSS v3.0 Risk Assessment & Prioritization</div>
        <div style="font-size: 0.82rem; color: {tokens['text_secondary']}; margin-top: 6px; line-height: 1.55;">
            Findings are scored using the official <strong>Common Vulnerability Scoring System (CVSS) v3.0</strong> base metric equations (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability).
            Defense-in-depth headers without verified exploit chains are marked <strong>Not Scored</strong> with missing evidence documented, avoiding speculative or ungrounded severity ratings.
        </div>
    </div>
    """)

    # Filter Toolbar
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)

    with f_col1:
        search_query = st.text_input("Search Findings", placeholder="Filter by title, host, category, vector...")

    with f_col2:
        cvss_filter_options = ["All", "Critical (9.0–10.0)", "High (7.0–8.9)", "Medium (4.0–6.9)", "Low (0.1–3.9)", "None (0.0)", "Not Scored"]
        selected_cvss = st.selectbox("CVSS v3.0 Severity", cvss_filter_options)

    with f_col3:
        statuses = ["All", "FAIL", "WARNING", "PASS"]
        selected_status = st.selectbox("Audit Status", statuses)

    with f_col4:
        hostnames = ["All Targets"] + sorted(list(set(f["hostname"] for f in all_findings)))
        selected_host = st.selectbox("Target Host", hostnames)

    # Filter evaluation
    filtered = all_findings
    if search_query.strip():
        q = search_query.lower()
        filtered = [
            f for f in filtered
            if q in f["title"].lower() 
            or q in f["hostname"].lower() 
            or q in (f.get("evidence") or "").lower() 
            or q in (f.get("category") or "").lower()
            or q in (f.get("cvss_vector") or "").lower()
        ]

    if selected_cvss != "All":
        if selected_cvss.startswith("Critical"):
            filtered = [f for f in filtered if f.get("cvss_severity") == "Critical"]
        elif selected_cvss.startswith("High"):
            filtered = [f for f in filtered if f.get("cvss_severity") == "High"]
        elif selected_cvss.startswith("Medium"):
            filtered = [f for f in filtered if f.get("cvss_severity") == "Medium"]
        elif selected_cvss.startswith("Low"):
            filtered = [f for f in filtered if f.get("cvss_severity") == "Low"]
        elif selected_cvss.startswith("None"):
            filtered = [f for f in filtered if f.get("cvss_severity") == "None" and f.get("cvss_status") == "SCORED"]
        elif selected_cvss == "Not Scored":
            filtered = [f for f in filtered if f.get("cvss_status") == "NOT_SCORED"]

    if selected_status != "All":
        filtered = [f for f in filtered if f["status"] == selected_status]

    if selected_host != "All Targets":
        filtered = [f for f in filtered if f["hostname"] == selected_host]

    st.markdown(f"<span style='font-size: 0.85rem; color: {tokens['text_muted']};'>Showing {len(filtered)} of {len(all_findings)} finding records</span>", unsafe_allow_html=True)
    st.write("")

    # Render Findings List
    for finding in filtered:
        status_pill = get_status_badge_html(finding["status"])
        v_status = finding.get("verification_status", "Open")
        v_color = get_verification_color(v_status)

        # CVSS metadata
        cvss_status = finding.get("cvss_status") or ("NOT_SCORED" if finding.get("cvss_score") is None else "SCORED")
        cvss_score = finding.get("cvss_score")
        cvss_sev = finding.get("cvss_severity") or "Not Scored"
        cvss_vec = finding.get("cvss_vector") or ""
        unscored_reason = finding.get("cvss_unscored_reason") or ""

        if cvss_status == "SCORED" and cvss_score is not None:
            score_label = f"CVSS {cvss_score:.1f} {cvss_sev.upper()}"
        else:
            score_label = "CVSS NOT SCORED"

        from ui.theme import get_cvss_badge_html
        cvss_badge = get_cvss_badge_html(cvss_score, cvss_sev, cvss_status)

        expander_title = f"[{score_label}] {finding['title']} — {finding['hostname']}"
        with st.expander(expander_title):
            col_l, col_r = st.columns([3, 1])

            with col_l:
                render_safe_html(f"""
                <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap;">
                    {cvss_badge} {status_pill}
                    <span style="font-size: 0.8rem; color: {tokens['text_secondary']};">Target: <code>{finding['hostname']}</code></span>
                    <span style="font-size: 0.8rem; color: {tokens['text_muted']};">Detected: {str(finding['scan_time'])[:19]}</span>
                </div>
                """)

                # CVSS Vector or Unscored Reason Callout
                if cvss_status == "SCORED" and cvss_vec:
                    render_safe_html(f"""
                    <div style="background: {tokens['surface_elevated']}; border: 1px solid {tokens['border']}; border-radius: 4px; padding: 6px 12px; margin-bottom: 12px; font-family: monospace; font-size: 0.78rem; color: {tokens['accent']}; display: flex; align-items: center; gap: 8px;">
                        <span style="font-weight: 700; color: {tokens['text_primary']};">CVSS v3.0 Vector:</span>
                        <span>{cvss_vec}</span>
                    </div>
                    """)
                elif cvss_status == "NOT_SCORED":
                    render_safe_html(f"""
                    <div style="background: {tokens['surface_elevated']}; border: 1px solid {tokens['border']}; border-left: 3px solid {tokens['warning']}; border-radius: 4px; padding: 8px 12px; margin-bottom: 12px;">
                        <div style="font-size: 0.75rem; font-weight: 700; color: {tokens['warning']}; text-transform: uppercase;">CVSS v3.0 Scoring Status: Not Scored</div>
                        <div style="font-size: 0.8rem; color: {tokens['text_secondary']}; margin-top: 2px;">
                            <strong>Missing Information / Technical Rationale:</strong> {unscored_reason or 'This finding represents a defense-in-depth configuration gap. Missing this defense does not provide sufficient evidence of an exploitable attack vector without a confirmed application vulnerability.'}
                        </div>
                    </div>
                    """)

                st.markdown("**Observed Evidence**")
                st.code(finding["evidence"], language="http")

                st.markdown(f"**Why It Matters:** {finding['why_it_matters']}")
                st.markdown(f"**Potential Adversary Impact:** {finding['potential_impact']}")
                st.markdown(f"**Recommended Remediation:** {finding['recommended_action']}")

            with col_r:
                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Lifecycle Status</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: {v_color}; margin: 4px 0;">{v_status}</div>
                </div>
                """)

                st.markdown("**Update Status**")
                options = ["Open", "In Progress", "Fixed", "Verified"]
                curr_idx = options.index(v_status) if v_status in options else 0
                new_status = st.selectbox(
                    "Set Status",
                    options,
                    index=curr_idx,
                    key=f"status_sel_{finding['id']}",
                    label_visibility="collapsed"
                )

                if st.button("Save", key=f"btn_save_{finding['id']}", use_container_width=True):
                    with get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE findings SET verification_status = ? WHERE id = ?", (new_status, finding["id"]))
                        conn.commit()
                    st.success("Status updated.")
                    st.rerun()
