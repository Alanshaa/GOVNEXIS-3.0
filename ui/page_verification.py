"""Before-and-After Security Verification for GOVNEXIS.

Workflow:
- Select Baseline Scan (Before) and Rescan (After)
- Score Delta calculation and trajectory visualization
- Differential finding analysis: Resolved, Remaining, and Regressed
- Side-by-side response header and cookie comparison
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any, List

from core.database import get_all_scans, get_scan
from ui.theme import (
    render_page_header,
    render_safe_html,
    get_tokens,
    get_score_color,
)


def render_verification_page() -> None:
    """Render Before-and-After Verification UI."""
    render_page_header(
        "Verification",
        "Empirical before-and-after comparison of baseline vs. follow-up scans",
    )
    tokens = get_tokens()

    render_safe_html(f"""
    <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-left: 4px solid {tokens['accent']}; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;">
        <div style="font-weight: 600; color: {tokens['accent']}; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.04em;">Empirical Verification Workflow</div>
        <div style="font-size: 0.82rem; color: {tokens['text_secondary']}; line-height: 1.5; margin-top: 4px;">
            A fix is only verified when demonstrated by a repeatable, empirical follow-up audit.
            Compare your baseline scan before applying remediation against your post-hardening verification scan.
        </div>
    </div>
    """)

    all_scans = get_all_scans(limit=50)
    if len(all_scans) < 2:
        st.info("At least two scans are required to perform a Before-and-After comparison. Run scans on the New Scan page or use the Demo Lab.")
        return

    # Select Scans for Comparison
    col_sel1, col_sel2 = st.columns(2)

    scan_options = {
        s["id"]: f"#{s['id']} | {s['hostname']} | CVSS v3.0: {s.get('max_cvss', 0.0):.1f} ({s.get('cvss_severity', 'None')}) | {s['timestamp'][:16]}"
        for s in all_scans
    }

    with col_sel1:
        baseline_id = st.selectbox(
            "Select Baseline Scan (Before)",
            options=list(scan_options.keys()),
            index=1 if len(scan_options) > 1 else 0,
            format_func=lambda x: scan_options[x]
        )

    with col_sel2:
        rescan_id = st.selectbox(
            "Select Follow-up Scan (After)",
            options=list(scan_options.keys()),
            index=0,
            format_func=lambda x: scan_options[x]
        )

    if baseline_id == rescan_id:
        st.warning("Please select two distinct scans to evaluate verification deltas.")
        return

    # Load Scan Details
    scan_a = get_scan(baseline_id)
    scan_b = get_scan(rescan_id)

    if not scan_a or not scan_b:
        st.error("Error loading selected scan records.")
        return

    from ui.theme import get_cvss_badge_html, get_cvss_color

    # CVSS maximum severity calculation
    cvss_scores_a = [f.get("cvss_score") for f in scan_a.get("findings", []) if f.get("cvss_status") == "SCORED" and f.get("cvss_score") is not None]
    cvss_scores_b = [f.get("cvss_score") for f in scan_b.get("findings", []) if f.get("cvss_status") == "SCORED" and f.get("cvss_score") is not None]
    max_cvss_a = max(cvss_scores_a) if cvss_scores_a else float(scan_a.get("max_cvss", 0.0))
    max_cvss_b = max(cvss_scores_b) if cvss_scores_b else float(scan_b.get("max_cvss", 0.0))
    cvss_delta = max_cvss_b - max_cvss_a

    sev_a = "CRITICAL" if max_cvss_a >= 9.0 else ("HIGH" if max_cvss_a >= 7.0 else ("MEDIUM" if max_cvss_a >= 4.0 else ("LOW" if max_cvss_a > 0 else "NONE")))
    sev_b = "CRITICAL" if max_cvss_b >= 9.0 else ("HIGH" if max_cvss_b >= 7.0 else ("MEDIUM" if max_cvss_b >= 4.0 else ("LOW" if max_cvss_b > 0 else "NONE")))

    # Pre-calculate differential items for resolution card
    findings_a = {f["check_id"]: f for f in scan_a.get("findings", [])}
    findings_b = {f["check_id"]: f for f in scan_b.get("findings", [])}

    resolved_items = []
    remaining_items = []
    regressed_items = []

    all_check_ids = sorted(list(set(list(findings_a.keys()) + list(findings_b.keys()))))

    for cid in all_check_ids:
        fa = findings_a.get(cid)
        fb = findings_b.get(cid)

        st_a = fa["status"] if fa else "N/A"
        st_b = fb["status"] if fb else "N/A"
        title = (fb or fa)["title"]
        f_obj = fb or fa

        if st_a in ("FAIL", "WARNING") and st_b == "PASS":
            resolved_items.append((title, st_a, st_b, f_obj))
        elif st_a in ("FAIL", "WARNING") and st_b in ("FAIL", "WARNING"):
            remaining_items.append((title, st_a, st_b, f_obj))
        elif st_a == "PASS" and st_b in ("FAIL", "WARNING"):
            regressed_items.append((title, st_a, st_b, f_obj))

    # Comparison Cards (CVSS v3.0 Matrix Only)
    st.write("")
    c_card1, c_card2, c_card3, c_card4 = st.columns(4)

    cvss_delta_color = tokens["accent"] if cvss_delta < 0 else (tokens["text_muted"] if cvss_delta == 0 else tokens["error"])
    cvss_delta_sign = f"{cvss_delta:+.1f}" if cvss_delta != 0 else "0.0"
    cvss_verdict = "Risk Reduced" if cvss_delta < 0 else ("Risk Increased" if cvss_delta > 0 else "Risk Unchanged")

    with c_card1:
        render_safe_html(f"""
        <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 8px; padding: 16px; text-align: center;">
            <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Baseline CVSS v3.0</div>
            <div style="font-size: 2.1rem; font-weight: 800; color: {get_cvss_color(max_cvss_a)}; margin: 4px 0;">{max_cvss_a:.1f}</div>
            <div style="font-size: 0.78rem; font-weight: 600; color: {get_cvss_color(max_cvss_a)};">Severity: {sev_a}</div>
        </div>
        """)

    with c_card2:
        render_safe_html(f"""
        <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 8px; padding: 16px; text-align: center;">
            <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Rescan CVSS v3.0</div>
            <div style="font-size: 2.1rem; font-weight: 800; color: {get_cvss_color(max_cvss_b)}; margin: 4px 0;">{max_cvss_b:.1f}</div>
            <div style="font-size: 0.78rem; font-weight: 600; color: {get_cvss_color(max_cvss_b)};">Severity: {sev_b}</div>
        </div>
        """)

    with c_card3:
        render_safe_html(f"""
        <div style="background: {tokens['surface']}; border: 1px solid {cvss_delta_color}; border-radius: 8px; padding: 16px; text-align: center;">
            <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">CVSS Risk Delta</div>
            <div style="font-size: 2.1rem; font-weight: 800; color: {cvss_delta_color}; margin: 4px 0;">{cvss_delta_sign}</div>
            <div style="font-size: 0.78rem; color: {cvss_delta_color}; font-weight: 600;">{cvss_verdict}</div>
        </div>
        """)

    with c_card4:
        res_color = tokens["accent"] if len(resolved_items) > 0 else tokens["text_muted"]
        render_safe_html(f"""
        <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 8px; padding: 16px; text-align: center;">
            <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Resolved Findings</div>
            <div style="font-size: 2.1rem; font-weight: 800; color: {res_color}; margin: 4px 0;">{len(resolved_items)}</div>
            <div style="font-size: 0.78rem; color: {tokens['text_secondary']};">Vulnerabilities Fixed</div>
        </div>
        """)

    # Detailed Rule-by-Rule Differential Analysis
    st.write("")
    st.markdown("#### Rule-by-Rule Differential Audit")

    findings_a = {f["check_id"]: f for f in scan_a.get("findings", [])}
    findings_b = {f["check_id"]: f for f in scan_b.get("findings", [])}

    resolved_items = []
    remaining_items = []
    regressed_items = []

    all_check_ids = sorted(list(set(list(findings_a.keys()) + list(findings_b.keys()))))

    for cid in all_check_ids:
        fa = findings_a.get(cid)
        fb = findings_b.get(cid)

        st_a = fa["status"] if fa else "N/A"
        st_b = fb["status"] if fb else "N/A"
        title = (fb or fa)["title"]
        f_obj = fb or fa

        if st_a in ("FAIL", "WARNING") and st_b == "PASS":
            resolved_items.append((title, st_a, st_b, f_obj))
        elif st_a in ("FAIL", "WARNING") and st_b in ("FAIL", "WARNING"):
            remaining_items.append((title, st_a, st_b, f_obj))
        elif st_a == "PASS" and st_b in ("FAIL", "WARNING"):
            regressed_items.append((title, st_a, st_b, f_obj))

    tab_res, tab_rem, tab_diff = st.tabs([
        f"Resolved Findings ({len(resolved_items)})",
        f"Remaining Issues ({len(remaining_items)})",
        "Header Comparison"
    ])

    with tab_res:
        if resolved_items:
            for title, before, after, f_obj in resolved_items:
                cvss_s = f_obj.get("cvss_score")
                cvss_sev = f_obj.get("cvss_severity", "None")
                cvss_st = f_obj.get("cvss_status", "SCORED")
                badge = get_cvss_badge_html(cvss_s, cvss_sev, cvss_st)
                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-left: 4px solid {tokens['accent']}; border-radius: 6px; padding: 12px 16px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <span style="font-weight: 600; color: {tokens['text_primary']};">{title}</span>
                        <div style="margin-top: 4px;">{badge}</div>
                    </div>
                    <div>
                        <span style="color: {tokens['error']}; text-decoration: line-through; font-size: 0.82rem; margin-right: 8px;">{before}</span>
                        <span style="color: {tokens['accent']}; font-weight: 700; font-size: 0.88rem;">&rarr; {after}</span>
                    </div>
                </div>
                """)
        else:
            st.info("No previously failed findings were resolved between these two scans.")

    with tab_rem:
        if remaining_items:
            for title, before, after, f_obj in remaining_items:
                cvss_s = f_obj.get("cvss_score")
                cvss_sev = f_obj.get("cvss_severity", "Not Scored")
                cvss_st = f_obj.get("cvss_status", "NOT_SCORED")
                badge = get_cvss_badge_html(cvss_s, cvss_sev, cvss_st)
                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-left: 4px solid {tokens['warning']}; border-radius: 6px; padding: 12px 16px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <span style="font-weight: 600; color: {tokens['text_primary']};">{title}</span>
                        <div style="margin-top: 4px;">{badge}</div>
                    </div>
                    <span style="color: {tokens['warning']}; font-size: 0.82rem; font-weight: 600;">Status: {after}</span>
                </div>
                """)
        else:
            st.success("All configuration checks passed in the follow-up scan.")

    with tab_diff:
        st.markdown("**Side-by-Side Header Observations**")
        headers_a = scan_a.get("details", {}).get("response_headers", {})
        headers_b = scan_b.get("details", {}).get("response_headers", {})

        all_header_keys = sorted(list(set(list(headers_a.keys()) + list(headers_b.keys()))))
        diff_rows = []
        for h in all_header_keys:
            val_a = headers_a.get(h, "<ABSENT>")
            val_b = headers_b.get(h, "<ABSENT>")
            diff_rows.append({
                "HTTP Header": h,
                "Baseline (Scan A)": val_a,
                "Rescan (Scan B)": val_b,
                "Changed": "YES" if val_a != val_b else "NO",
            })

        st.dataframe(pd.DataFrame(diff_rows), use_container_width=True, hide_index=True)
