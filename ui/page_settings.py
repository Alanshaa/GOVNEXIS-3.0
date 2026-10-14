"""Settings, Methodology and Guided Help for GOVNEXIS.

Contains:
- Product identity, mission statement, and core architecture
- Theme & appearance preferences
- Transparent scoring methodology and check weights reference table
- Guided troubleshooting for common network and TLS failure modes
- Legal authorization notice and defensive auditing disclaimers
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any

from core.config import (
    APP_NAME, APP_TAGLINE, APP_DESCRIPTION, APP_CATEGORY, APP_VERSION,
    CHECK_WEIGHTS
)
from ui.theme import (
    render_page_header,
    render_safe_html,
    get_current_theme,
    set_theme,
    get_tokens,
    THEME_DARK,
    THEME_LIGHT,
)


def render_settings_page() -> None:
    """Render Settings, Methodology and Guided Help page."""
    render_page_header(
        "Settings & Documentation",
        "System architecture, transparent scoring methodology, and guided troubleshooting",
    )
    tokens = get_tokens()
    current_theme = get_current_theme()

    tab_about, tab_theme, tab_scoring, tab_help, tab_legal = st.tabs([
        "About GOVNEXIS",
        "Theme & Appearance",
        "Scoring Methodology",
        "Guided Troubleshooting",
        "Legal & Ethical Notice",
    ])

    with tab_about:
        st.subheader(f"{APP_NAME} — {APP_CATEGORY}")
        st.markdown(f"> *\"{APP_TAGLINE}\"*")
        st.markdown(f"**Description:** {APP_DESCRIPTION}")

        st.markdown("""
        #### Core Capabilities
        1. **Passive Defense-Only Auditing**: Evaluates public HTTP response headers, cookie attributes, and TLS protocol observations without invasive payloads.
        2. **Transparent Scoring**: Deterministic 0–100 scale grounded directly in federal and international standards (CISA BOD 18-01, NIST SP 800-52r2, OWASP).
        3. **Remediation Knowledge Base**: Actionable configuration playbooks for Nginx, Apache, Caddy, Node.js, and Python.
        4. **Empirical Before-and-After Verification**: Side-by-side verification proving that remediations genuinely resolved configuration gaps.
        5. **Isolated Local Demo Lab**: Safe sandbox test harness on `127.0.0.1:8765` for hackathon evaluation and air-gapped testing.
        """)

        st.divider()
        st.caption(f"GOVNEXIS Core Engine v{APP_VERSION} | Python 3 | SQLite 3 | Streamlit")

    with tab_theme:
        st.subheader("Appearance & Design System")
        st.markdown("GOVNEXIS supports dark and light modes. Your preference is persisted across browser refreshes and sessions.")

        col_t1, col_t2 = st.columns([2, 2])
        with col_t1:
            theme_choice = st.radio(
                "Interface Theme",
                [THEME_DARK, THEME_LIGHT],
                index=0 if current_theme == THEME_DARK else 1,
                format_func=lambda x: f"Dark Mode ({x.title()})" if x == THEME_DARK else f"Light Mode ({x.title()})",
                horizontal=True
            )
            if theme_choice != current_theme:
                set_theme(theme_choice)
                st.rerun()

        with col_t2:
            st.markdown(f"""
            <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 6px; padding: 12px 16px;">
                <div style="font-size: 0.75rem; color: {tokens['text_muted']}; font-weight: 600; text-transform: uppercase;">Active Theme</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: {tokens['accent']}; margin: 4px 0;">{current_theme.upper()}</div>
                <div style="font-size: 0.8rem; color: {tokens['text_secondary']};">Tokens loaded from centralized design system</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("#### Design Palette Tokens")
        token_rows = [
            {"Token": "Background", "Hex": tokens["bg"], "Description": "Main application canvas"},
            {"Token": "Surface", "Hex": tokens["surface"], "Description": "Card and container backgrounds"},
            {"Token": "Surface Elevated", "Hex": tokens["surface_elevated"], "Description": "Raised elements and inputs"},
            {"Token": "Primary Text", "Hex": tokens["text_primary"], "Description": "High contrast body and titles"},
            {"Token": "Secondary Text", "Hex": tokens["text_secondary"], "Description": "Descriptions and secondary content"},
            {"Token": "Borders", "Hex": tokens["border"], "Description": "Subtle structural separators"},
            {"Token": "Primary Accent", "Hex": tokens["accent"], "Description": "Muted emerald for primary actions"},
            {"Token": "Secondary Accent", "Hex": tokens["accent_teal"], "Description": "Restrained teal for secondary highlights"},
            {"Token": "Warning", "Hex": tokens["warning"], "Description": "Amber warning indicators"},
            {"Token": "Error", "Hex": tokens["error"], "Description": "Accessible muted red failure indicators"},
        ]
        st.dataframe(pd.DataFrame(token_rows), use_container_width=True, hide_index=True)

    with tab_scoring:
        st.subheader("Official CVSS v3.0 Vulnerability Severity Matrix")
        st.markdown("""
        GOVNEXIS exclusively uses the official **Common Vulnerability Scoring System (CVSS) v3.0 methodology** 
        (published by FIRST) as its sole risk-scoring matrix across the entire platform. The legacy custom 0–100 scoring matrix has been completely removed in favor of this standardized, internationally recognized vulnerability severity standard.
        """)

        st.markdown("---")
        st.markdown("### 1. Official CVSS v3.0 Methodology")
        st.markdown("""
        GOVNEXIS strictly implements the official **CVSS v3.0 specification** (not v3.1, v4.0, or custom heuristics) published by FIRST (Forum of Incident Response and Security Teams).

        #### Metric Categories & Coefficients:
        - **Exploitability Metrics**:
          - **Attack Vector (AV)**: Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.20)
          - **Attack Complexity (AC)**: Low (0.77), High (0.44)
          - **Privileges Required (PR)**: Scope-dependent:
            - *Scope Unchanged*: None (0.85), Low (0.62), High (0.27)
            - *Scope Changed*: None (0.85), Low (0.68), High (0.50)
          - **User Interaction (UI)**: None (0.85), Required (0.62)
        - **Impact Metrics**:
          - **Scope (S)**: Unchanged (U) or Changed (C)
          - **Confidentiality (C)**, **Integrity (I)**, **Availability (A)**: None (0.0), Low (0.22), High (0.56)

        #### Official Base Score Formula:
        $$ISS = 1 - [ (1 - C) \\times (1 - I) \\times (1 - A) ]$$
        
        - If Scope is **Unchanged**:
          $$Impact = 6.42 \\times ISS$$
          $$BaseScore = Roundup(\\min(Impact + Exploitability, 10))$$
        - If Scope is **Changed**:
          $$Impact = 7.52 \\times (ISS - 0.029) - 3.25 \\times (ISS - 0.02)^{15}$$
          $$BaseScore = Roundup(\\min(1.08 \\times (Impact + Exploitability), 10))$$
        - Where:
          $$Exploitability = 8.22 \\times AV \\times AC \\times PR \\times UI$$
          If $Impact \\le 0$, $BaseScore = 0.0$.

        #### Official Roundup Rule:
        CVSS v3.0 defines `Roundup(x)` as the smallest number, specified to one decimal place, that is greater than or equal to the input parameter (e.g. 4.02 rounds to 4.1).

        #### Official Severity Scale:
        - **None**: 0.0
        - **Low**: 0.1 – 3.9
        - **Medium**: 4.0 – 6.9
        - **High**: 7.0 – 8.9
        - **Critical**: 9.0 – 10.0
        """)

        st.markdown("---")
        st.markdown("### 2. Defensible Finding Mappings & 'Not Scored' Designation")
        st.markdown("""
        > **Strict Grounding Rule**: Missing HTTP defense-in-depth headers are **NOT** proof of an exploitable vulnerability.
        
        Under CVSS v3.0, scoring requires defensible evidence of an attack path. When an audit cannot confirm a vulnerable application endpoint, the finding is marked **Not Scored** with an explicit statement of missing technical evidence to prevent artificial risk inflation.
        """)

        mapping_rows = [
            {"Security Rule": "Transport Security (HTTPS)", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "CVSS Score & Severity": "7.4 High", "Scoring Basis": "Plaintext MITM interception & modification"},
            {"Security Rule": "Strict-Transport-Security (HSTS)", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", "CVSS Score & Severity": "6.8 Medium", "Scoring Basis": "SSL-stripping on initial connection downgrade"},
            {"Security Rule": "Clickjacking Defense (XFO)", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "CVSS Score & Severity": "4.3 Medium", "Scoring Basis": "UI redress click-jacking without framing restriction"},
            {"Security Rule": "Cookie Security (Secure/HttpOnly)", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", "CVSS Score & Severity": "5.3 Medium", "Scoring Basis": "Network sniffing or XSS credential theft of sensitive cookie"},
            {"Security Rule": "Server Information Disclosure", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CVSS Score & Severity": "5.3 Medium", "Scoring Basis": "Reconnaissance version leak for unpatched targeting"},
            {"Security Rule": "TLS Certificate / Protocols", "CVSS v3.0 Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CVSS Score & Severity": "7.5 High", "Scoring Basis": "Expired/untrusted certificate halts service availability"},
            {"Security Rule": "Content Security Policy (CSP)", "CVSS v3.0 Vector": "N/A — Not Scored", "CVSS Score & Severity": "Not Scored", "Scoring Basis": "Defense-in-depth: Requires confirmed XSS injection flaw"},
            {"Security Rule": "Permissions-Policy", "CVSS v3.0 Vector": "N/A — Not Scored", "CVSS Score & Severity": "Not Scored", "Scoring Basis": "Defense-in-depth: Requires device API exploitation path"},
            {"Security Rule": "Referrer-Policy", "CVSS v3.0 Vector": "N/A — Not Scored", "CVSS Score & Severity": "Not Scored", "Scoring Basis": "Defense-in-depth: Requires sensitive URL token leakage"},
            {"Security Rule": "MIME-Sniffing (XCTO)", "CVSS v3.0 Vector": "N/A — Not Scored", "CVSS Score & Severity": "Not Scored", "Scoring Basis": "Defense-in-depth: Requires file upload or content reflection"},
        ]
        st.dataframe(pd.DataFrame(mapping_rows), use_container_width=True, hide_index=True)

        st.warning("""
        **Limitation Disclaimer**: CVSS v3.0 scores evaluate the intrinsic technical severity of vulnerabilities under standardized worst-case assumptions. 
        A CVSS score is **not** a guarantee that an attack will or will not occur, nor does it replace threat modeling or context-aware defense.
        """)

    with tab_help:
        st.subheader("Guided Troubleshooting & Plain-English Error Help")
        st.markdown("If an audit scan fails to complete, refer to the diagnostic guide below:")

        errors = [
            {
                "Issue": "DNS Resolution Failure",
                "Plain English": "The domain name could not be resolved to an IP address.",
                "Action": "Check spelling of the domain. Verify the domain is publicly registered and active in DNS."
            },
            {
                "Issue": "Connection Timed Out",
                "Plain English": "The server did not respond to initial TCP connection requests within 5.0 seconds.",
                "Action": "Ensure the web server is running and port 80/443 is open. Check if an external firewall is dropping requests."
            },
            {
                "Issue": "SSRF / Destination Blocked",
                "Plain English": "The URL resolved to a loopback, private (RFC 1918), or reserved IP address.",
                "Action": "GOVNEXIS blocks scans against internal infrastructure to protect against SSRF. For sandbox testing, use the designated Local Demo Lab."
            },
            {
                "Issue": "TLS / SSL Handshake Failure",
                "Plain English": "The server's TLS certificate is invalid, expired, self-signed, or the server rejects HTTPS.",
                "Action": "Verify that a valid CA-signed certificate is installed and bound to port 443."
            },
            {
                "Issue": "Too Many Redirects (>5)",
                "Plain English": "The URL initiated a circular or excessively long chain of HTTP redirects.",
                "Action": "Audit server redirect rules (e.g. infinite HTTP to HTTPS loop caused by reverse proxy misconfiguration)."
            }
        ]

        for e in errors:
            with st.expander(e["Issue"]):
                st.markdown(f"**What Happened:** {e['Plain English']}")
                st.markdown(f"**Recommended Action:** {e['Action']}")

    with tab_legal:
        st.subheader("Legal Authorization & Ethical Assessment Notice")
        st.markdown("""
        **Notice of Intended Use:**
        GOVNEXIS is developed strictly as a defensive auditing and educational platform. 
        It is intended solely for authorized system administrators, security officers, and website owners 
        evaluating their own public web infrastructure.

        **Protective Constraints:**
        - No intrusive port scans, vulnerability exploits, or brute-force tests are performed.
        - Users must explicitly certify ownership or written permission prior to scanning.
        - All external scans enforce rate limits, strict timeouts, and SSRF destination filters.
        """)
