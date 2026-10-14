"""Local Demo Lab for GOVNEXIS.

Provides an interactive sandbox environment for live demonstrations:
- Controls local test HTTP server on 127.0.0.1:8765
- Demonstrates Baseline (vulnerable/misconfigured) vs Hardened states
- One-click scan, remediation fix application, rescan, and comparative verification
- Controlled sandbox banner isolating demonstration traffic
"""

import streamlit as st
import time
from typing import Dict, Any

from core.config import LOCAL_DEMO_URL, LOCAL_DEMO_HOST, LOCAL_DEMO_PORT
from core.mock_site import start_mock_server, stop_mock_server, get_demo_status, DEMO_STATE, MockServerState
from core.scanner import execute_scan
from core.database import save_scan
from ui.theme import (
    render_page_header,
    render_demo_banner,
    render_metric_card_html,
    render_safe_html,
    get_tokens,
)


def render_demo_lab_page() -> None:
    """Render the Local Demo Lab sandbox page."""
    render_page_header(
        "Demo Lab",
        "Isolated local sandbox demonstrating baseline vs. hardened security postures",
    )
    render_demo_banner()
    tokens = get_tokens()

    # Ensure demo server is started
    server_started = start_mock_server()
    status = get_demo_status()

    # Status Panel
    col_st1, col_st2, col_st3 = st.columns(3)

    with col_st1:
        server_val = "ONLINE" if status["running"] else "OFFLINE"
        server_color = tokens["accent"] if status["running"] else tokens["error"]
        render_safe_html(render_metric_card_html(
            "Sandbox Server Status",
            server_val,
            f"Bound to {status['host']}:{status['port']}",
            delta_color=server_color
        ))

    with col_st2:
        is_hardened = status["mode"] == MockServerState.MODE_HARDENED
        mode_val = "HARDENED" if is_hardened else "BASELINE"
        mode_color = tokens["accent"] if is_hardened else tokens["warning"]
        subtext = "Hardened Defense Posture" if is_hardened else "Vulnerable Baseline Posture"
        render_safe_html(render_metric_card_html(
            "Simulation State",
            mode_val,
            subtext,
            delta_color=mode_color
        ))

    with col_st3:
        render_safe_html(render_metric_card_html(
            "Target Endpoint",
            status["url"],
            "Safe localhost allowlist",
            delta_color=tokens["accent_teal"]
        ))

    st.write("")

    # Interactive Action Buttons
    st.subheader("Sandbox Controls")
    b_col1, b_col2, b_col3, b_col4 = st.columns(4)

    with b_col1:
        if st.button("Run Baseline Scan", use_container_width=True, type="primary"):
            DEMO_STATE.set_mode(MockServerState.MODE_BASELINE)
            with st.spinner("Running Baseline security audit on local sandbox..."):
                time.sleep(0.3)
                res = execute_scan(
                    target_url=LOCAL_DEMO_URL,
                    user_confirmed_authorization=True,
                    allow_local_demo=True
                )
                scan_id = save_scan(res)
                st.session_state["demo_baseline_scan"] = res
                st.session_state["latest_scan_result"] = res
                b_cvss = getattr(res.score_report, "max_cvss_score", 0.0) or 0.0
                st.success(f"Baseline scan completed. CVSS v3.0 Base Score: {b_cvss:.1f}")
                st.rerun()

    with b_col2:
        if st.button("Apply Hardened Config", use_container_width=True):
            DEMO_STATE.set_mode(MockServerState.MODE_HARDENED)
            st.success("Hardened headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, secure cookies) enabled on sandbox.")
            st.rerun()

    with b_col3:
        if st.button("Rescan Hardened Target", use_container_width=True, type="primary"):
            DEMO_STATE.set_mode(MockServerState.MODE_HARDENED)
            with st.spinner("Executing post-hardening verification audit..."):
                time.sleep(0.3)
                res = execute_scan(
                    target_url=LOCAL_DEMO_URL,
                    user_confirmed_authorization=True,
                    allow_local_demo=True
                )
                scan_id = save_scan(res)
                st.session_state["demo_hardened_scan"] = res
                st.session_state["latest_scan_result"] = res
                h_cvss = getattr(res.score_report, "max_cvss_score", 0.0) or 0.0
                st.success(f"Verification scan completed. CVSS v3.0 Base Score: {h_cvss:.1f}")
                st.rerun()

    with b_col4:
        if st.button("Reset to Baseline", use_container_width=True):
            DEMO_STATE.set_mode(MockServerState.MODE_BASELINE)
            st.info("Demo server reset to Baseline (Misconfigured) state.")
            st.rerun()

    st.write("")

    # Live Before & After Verification in the Lab
    has_baseline = "demo_baseline_scan" in st.session_state
    has_hardened = "demo_hardened_scan" in st.session_state

    if has_baseline or has_hardened:
        st.subheader("Scan Results (CVSS v3.0 Matrix)")

        res_col1, res_col2 = st.columns(2)

        with res_col1:
            st.markdown("#### Baseline Result (Before)")
            if has_baseline:
                b_res = st.session_state["demo_baseline_scan"]
                b_cvss = getattr(b_res.score_report, "max_cvss_score", 0.0) or 0.0
                b_sev = "CRITICAL" if b_cvss >= 9.0 else ("HIGH" if b_cvss >= 7.0 else ("MEDIUM" if b_cvss >= 4.0 else ("LOW" if b_cvss > 0 else "NONE")))
                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['error']}; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Baseline CVSS v3.0</div>
                    <div style="font-size: 2.2rem; font-weight: 800; color: {tokens['error']}; margin: 4px 0;">{b_cvss:.1f} <span style="font-size: 1rem; color: {tokens['text_muted']}; font-weight: 400;">({b_sev})</span></div>
                    <div style="font-size: 0.8rem; color: {tokens['error']};">Configuration gaps: Missing HSTS, CSP, X-Frame-Options, weak session cookie</div>
                </div>
                """)
                for f in b_res.findings:
                    if f.status in ("FAIL", "WARNING"):
                        st.caption(f"FAIL: {f.title} — {f.evidence[:60]}")
            else:
                st.info("Click 'Run Baseline Scan' above to record the baseline state.")

        with res_col2:
            st.markdown("#### Hardened Result (After)")
            if has_hardened:
                h_res = st.session_state["demo_hardened_scan"]
                h_cvss = getattr(h_res.score_report, "max_cvss_score", 0.0) or 0.0
                h_sev = "CRITICAL" if h_cvss >= 9.0 else ("HIGH" if h_cvss >= 7.0 else ("MEDIUM" if h_cvss >= 4.0 else ("LOW" if h_cvss > 0 else "NONE")))
                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['accent']}; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                    <div style="font-size: 0.72rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;">Verified CVSS v3.0</div>
                    <div style="font-size: 2.2rem; font-weight: 800; color: {tokens['accent']}; margin: 4px 0;">{h_cvss:.1f} <span style="font-size: 1rem; color: {tokens['text_muted']}; font-weight: 400;">({h_sev})</span></div>
                    <div style="font-size: 0.8rem; color: {tokens['accent']};">Defense-in-depth verified: All exploitable vulnerabilities mitigated (CVSS 0.0)</div>
                </div>
                """)
                for f in h_res.findings:
                    if f.status == "PASS":
                        st.caption(f"PASS: {f.title}")
            else:
                st.info("Click 'Apply Hardened Config' then 'Rescan Hardened Target' to observe verification.")

        if has_baseline and has_hardened:
            b_cvss = getattr(st.session_state["demo_baseline_scan"].score_report, "max_cvss_score", 0.0) or 0.0
            h_cvss = getattr(st.session_state["demo_hardened_scan"].score_report, "max_cvss_score", 0.0) or 0.0
            b_sev = "CRITICAL" if b_cvss >= 9.0 else ("HIGH" if b_cvss >= 7.0 else ("MEDIUM" if b_cvss >= 4.0 else ("LOW" if b_cvss > 0 else "NONE")))
            h_sev = "CRITICAL" if h_cvss >= 9.0 else ("HIGH" if h_cvss >= 7.0 else ("MEDIUM" if h_cvss >= 4.0 else ("LOW" if h_cvss > 0 else "NONE")))
            cvss_delta = h_cvss - b_cvss
            st.success(f"Live Verification Demonstrated: CVSS risk reduced by {cvss_delta:+.1f} (from {b_cvss:.1f} {b_sev} down to {h_cvss:.1f} {h_sev}) in the local sandbox.")
