"""Security Scanner Page for GOVNEXIS.

Handles:
- Target URL entry and authorization confirmation
- Multi-phase scan progress display
- Scan result rendering (score, findings, export buttons)
"""

import time
import streamlit as st
from urllib.parse import urlparse

from core.config import LOCAL_DEMO_URL, LOCAL_DEMO_HOST, LOCAL_DEMO_PORT
from core.scanner import execute_scan, ScanResult, ScanError
from core.url_validator import ValidationError, SSRFSecurityError
from core.database import save_scan
from core.reports import (
    generate_json_report, generate_html_report,
    generate_csv_report, generate_pdf_report,
)
from ui.theme import (
    render_page_header, render_info_banner, render_safe_html,
    get_status_badge_html, get_severity_badge_html,
    get_score_color, get_tokens,
)


def render_scanner_page():
    """Render the security scanner interface."""
    render_page_header(
        "New Security Scan",
        "Defensive configuration audit of HTTP headers, cookies, and TLS parameters.",
    )

    # Scope notice
    render_info_banner(
        "Defensive Configuration Audit Only",
        "GOVNEXIS inspects public HTTP response headers, cookie flags, and TLS "
        "connection parameters. It performs no port scanning, brute force attacks, "
        "or destructive testing. Scanning requires verified authorization.",
    )

    # Quick-fill buttons
    col_pre1, col_pre2, _ = st.columns([1.5, 1.5, 2])
    with col_pre1:
        if st.button("Fill Local Demo Target", use_container_width=True):
            st.session_state["scan_input_url"] = LOCAL_DEMO_URL
            st.session_state["scan_auth_checked"] = True
    with col_pre2:
        if st.button("Fill Public Example", use_container_width=True):
            st.session_state["scan_input_url"] = "https://example.gov"
            st.session_state["scan_auth_checked"] = True

    default_url = st.session_state.get("scan_input_url", "")
    default_auth = st.session_state.get("scan_auth_checked", False)

    # Scan form
    with st.form("scan_execution_form"):
        col_url, col_scheme = st.columns([3, 1])

        with col_url:
            target_url = st.text_input(
                "Website Target URL",
                value=default_url,
                placeholder="https://agency.example.gov or 127.0.0.1:8765",
                help="Enter full URL or domain. HTTP or HTTPS schemes only.",
            )

        with col_scheme:
            is_https = target_url.lower().startswith("https://")
            if target_url:
                scheme_badge = "HTTPS (Encrypted)" if is_https else "HTTP (Plaintext)"
            else:
                scheme_badge = "Awaiting URL"
            st.text_input("Protocol", value=scheme_badge, disabled=True)

        auth_confirmed = st.checkbox(
            "I certify that I am the authorized website owner, administrator, "
            "or have explicit written permission to audit this endpoint.",
            value=default_auth,
            help="Mandatory authorization confirmation.",
        )

        submit_scan = st.form_submit_button(
            "Start Security Audit", type="primary", use_container_width=True,
        )

    # ---- Execution handler ----
    if submit_scan:
        if not target_url.strip():
            st.error("Please enter a valid website URL to audit.")
            return

        if not auth_confirmed:
            st.error("Scan halted: You must certify authorization before proceeding.")
            return

        # Determine if this is a local demo target
        allow_demo = False
        parsed = urlparse(
            target_url if target_url.startswith(("http://", "https://"))
            else "https://" + target_url
        )
        if parsed.hostname in ("127.0.0.1", "localhost") and parsed.port == LOCAL_DEMO_PORT:
            allow_demo = True

        progress_ph = st.empty()
        status_ph = st.empty()

        try:
            bar = progress_ph.progress(10)
            status_ph.caption("Phase 1/5: Validating URL syntax and SSRF restrictions...")
            time.sleep(0.15)

            bar.progress(35)
            status_ph.caption("Phase 2/5: Resolving DNS and verifying destination ranges...")
            time.sleep(0.15)

            bar.progress(60)
            status_ph.caption("Phase 3/5: Dispatching HTTP request and inspecting TLS...")

            scan_result = execute_scan(
                target_url=target_url,
                user_confirmed_authorization=True,
                allow_local_demo=allow_demo,
            )

            bar.progress(85)
            status_ph.caption("Phase 4/5: Evaluating security configuration rules...")
            time.sleep(0.15)

            bar.progress(100)
            status_ph.caption("Phase 5/5: Calculating score and saving record...")

            scan_id = save_scan(scan_result)
            st.session_state["latest_scan_result"] = scan_result
            st.session_state["latest_scan_id"] = scan_id

            progress_ph.empty()
            status_ph.empty()
            st.success(f"Audit completed. Scan record #{scan_id} saved.")

        except SSRFSecurityError as exc:
            progress_ph.empty()
            status_ph.empty()
            st.error(f"**Security Policy**: {exc}")
            st.info(
                "GOVNEXIS blocks internal IPs (10.x, 192.168.x, 127.x) to protect "
                "against SSRF. Use the Demo Lab for sandbox testing."
            )
            return
        except ValidationError as exc:
            progress_ph.empty()
            status_ph.empty()
            st.error(f"**Validation Error**: {exc}")
            return
        except ScanError as exc:
            progress_ph.empty()
            status_ph.empty()
            st.error(f"**Scan Error**: {exc.message}")
            if exc.technical_details:
                st.caption(f"Details: {exc.technical_details}")
            if exc.remediation_hint:
                st.info(f"Guidance: {exc.remediation_hint}")
            return
        except Exception as exc:
            progress_ph.empty()
            status_ph.empty()
            st.error(f"Unexpected failure: {exc}")
            return

    # Render results if available
    if "latest_scan_result" in st.session_state:
        _render_scan_results(st.session_state["latest_scan_result"])


# ---------------------------------------------------------------------------
# Results renderer
# ---------------------------------------------------------------------------

def _render_scan_results(res: ScanResult):
    """Render the scan result detail view with dual Configuration & CVSS v3.0 metrics."""
    t = get_tokens()
    from ui.theme import get_cvss_badge_html, get_cvss_color

    score = res.score_report.final_score
    grade = res.score_report.letter_grade
    score_color = get_score_color(score)

    max_cvss = getattr(res.score_report, "max_cvss_score", 0.0)
    cvss_color = get_cvss_color(max_cvss)
    cvss_dist = getattr(res.score_report, "cvss_severity_distribution", {})

    pass_count = sum(1 for f in res.findings if f.status == "PASS")
    fail_count = sum(1 for f in res.findings if f.status == "FAIL")
    warn_count = sum(1 for f in res.findings if f.status == "WARNING")

    st.markdown("---")

    # Score + summary row (CVSS v3.0 Matrix Only)
    col_score, col_meta = st.columns([1.2, 2.8])

    cvss_label = f"{max_cvss:.1f}" if max_cvss > 0 else "0.0"
    cvss_sev_str = (
        "CRITICAL" if max_cvss >= 9.0 else
        "HIGH" if max_cvss >= 7.0 else
        "MEDIUM" if max_cvss >= 4.0 else
        "LOW" if max_cvss > 0 else "NONE"
    )

    with col_score:
        render_safe_html(f"""
        <div class="gn-score-box" style="border:2px solid {cvss_color}; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 18px 12px;">
            <div style="font-size:0.72rem; color:{t['text_muted']}; font-weight:600; text-transform:uppercase; letter-spacing:0.05em;">
                CVSS v3.0 Base Score</div>
            <div style="font-size:3.2rem; font-weight:800; color:{cvss_color}; line-height:1.05; margin: 6px 0;">
                {cvss_label}</div>
            <div style="font-size:0.95rem; font-weight:700; color:{cvss_color}; text-transform:uppercase; letter-spacing:0.04em;">
                Severity: {cvss_sev_str}</div>
            <div style="font-size:0.72rem; color:{t['text_secondary']}; margin-top:6px;">
                Official FIRST Risk Metric</div>
        </div>
        """)

    with col_meta:
        render_safe_html(f"""
        <div style="background:{t['surface']}; border:1px solid {t['border']};
                    border-radius:8px; padding:16px; height: 100%;">
            <div style="display:flex; justify-content:space-between; align-items:center;
                        border-bottom:1px solid {t['border']}; padding-bottom:8px; margin-bottom:10px;">
                <span style="font-weight:700; color:{t['text_primary']}; font-size:0.95rem;">
                    Target: {res.hostname}</span>
                <span style="font-size:0.8rem; color:{t['text_secondary']};">
                    Duration: {res.duration_ms} ms</span>
            </div>
            <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:8px; text-align:center;">
                <div style="background:{t['success_bg']}; border:1px solid {t['success']};
                            border-radius:6px; padding:8px;">
                    <div style="font-size:1.2rem; font-weight:800; color:{t['success']};">{pass_count}</div>
                    <div style="font-size:0.7rem; color:{t['text_secondary']}; font-weight:600;">PASSED</div>
                </div>
                <div style="background:{t['error_bg']}; border:1px solid {t['error']};
                            border-radius:6px; padding:8px;">
                    <div style="font-size:1.2rem; font-weight:800; color:{t['error']};">{fail_count}</div>
                    <div style="font-size:0.7rem; color:{t['text_secondary']}; font-weight:600;">FAILED</div>
                </div>
                <div style="background:{t['warning_bg']}; border:1px solid {t['warning']};
                            border-radius:6px; padding:8px;">
                    <div style="font-size:1.2rem; font-weight:800; color:{t['warning']};">{warn_count}</div>
                    <div style="font-size:0.7rem; color:{t['text_secondary']}; font-weight:600;">WARNINGS</div>
                </div>
            </div>
            <div style="margin-top:8px; font-size:0.78rem; color:{t['text_secondary']};">
                <strong>Audit Target:</strong> <code>{res.final_url}</code> (HTTP {res.status_code})
            </div>
        </div>
        """)

    # Export toolbar
    st.markdown("")
    st.markdown("##### Export Assessment Report")
    scan_dict = res.to_dict()
    e1, e2, e3, e4 = st.columns(4)

    with e1:
        st.download_button(
            "PDF Report", data=generate_pdf_report(scan_dict),
            file_name=f"GOVNEXIS-Audit-{res.hostname}.pdf",
            mime="application/pdf", use_container_width=True,
        )
    with e2:
        st.download_button(
            "HTML Report", data=generate_html_report(scan_dict),
            file_name=f"GOVNEXIS-Audit-{res.hostname}.html",
            mime="text/html", use_container_width=True,
        )
    with e3:
        st.download_button(
            "JSON Data", data=generate_json_report(scan_dict),
            file_name=f"GOVNEXIS-Audit-{res.hostname}.json",
            mime="application/json", use_container_width=True,
        )
    with e4:
        st.download_button(
            "CSV Table", data=generate_csv_report(scan_dict),
            file_name=f"GOVNEXIS-Audit-{res.hostname}.csv",
            mime="text/csv", use_container_width=True,
        )

    # Detailed findings
    st.markdown("")
    st.markdown("##### Evaluated Security Checks & CVSS v3.0 Severity")

    for f in res.findings:
        status_pill = get_status_badge_html(f.status)

        # CVSS attributes
        cvss_obj = getattr(f, "cvss", None)
        cvss_score = getattr(cvss_obj, "base_score", None) if cvss_obj else None
        cvss_sev = getattr(cvss_obj, "severity", "Not Scored") if cvss_obj else "Not Scored"
        cvss_status = getattr(cvss_obj, "status", "NOT_SCORED") if cvss_obj else "NOT_SCORED"
        cvss_vec = getattr(cvss_obj, "vector_string", "") if cvss_obj else ""
        unscored_reason = getattr(cvss_obj, "unscored_reason", "") if cvss_obj else ""

        cvss_badge = get_cvss_badge_html(cvss_score, cvss_sev, cvss_status)

        header_score = f"CVSS {cvss_score:.1f} {cvss_sev.upper()}" if cvss_status == "SCORED" and cvss_score is not None else "CVSS NOT SCORED"

        with st.expander(f"[{header_score}] {f.status} — {f.title}"):
            c1, c2 = st.columns([3, 1])
            with c1:
                render_safe_html(f"""
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 10px; flex-wrap: wrap;">
                    {cvss_badge} {status_pill}
                    <span style="font-size: 0.8rem; color: {t['text_secondary']};">Category: <code>{f.category}</code></span>
                </div>
                """)

                if cvss_status == "SCORED" and cvss_vec:
                    render_safe_html(f"""
                    <div style="background: {t['surface_elevated']}; border: 1px solid {t['border']}; border-radius: 4px; padding: 6px 12px; margin-bottom: 12px; font-family: monospace; font-size: 0.78rem; color: {t['accent']}; display: flex; align-items: center; gap: 8px;">
                        <span style="font-weight: 700; color: {t['text_primary']};">CVSS v3.0 Vector:</span>
                        <span>{cvss_vec}</span>
                    </div>
                    """)
                elif cvss_status == "NOT_SCORED":
                    render_safe_html(f"""
                    <div style="background: {t['surface_elevated']}; border: 1px solid {t['border']}; border-left: 3px solid {t['warning']}; border-radius: 4px; padding: 8px 12px; margin-bottom: 12px;">
                        <div style="font-size: 0.75rem; font-weight: 700; color: {t['warning']}; text-transform: uppercase;">CVSS v3.0 Status: Not Scored</div>
                        <div style="font-size: 0.8rem; color: {t['text_secondary']}; margin-top: 2px;">
                            <strong>Technical Rationale:</strong> {unscored_reason or 'This finding is an architectural defense-in-depth configuration. Without verified application-layer exploitability, CVSS v3.0 cannot be defensibly calculated.'}
                        </div>
                    </div>
                    """)

                st.markdown("**Observed Evidence:**")
                st.code(f.evidence, language="http")
                st.markdown(f"**Why It Matters:** {f.why_it_matters}")
                st.markdown(f"**Potential Impact:** {f.potential_impact}")
                st.markdown(f"**Recommended Action:** {f.recommended_action}")
            with c2:
                st.markdown("**References:**")
                for ref in f.references:
                    st.markdown(f"- [{ref['title']}]({ref['url']})")
                st.caption(f"Confidence: {f.confidence}")
