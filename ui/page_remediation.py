"""Remediation Lab for GOVNEXIS.

Practical engineering guidance for resolving security configuration gaps:
- Copyable production snippets for Nginx, Apache, Caddy, Node.js, and Python
- Compatibility considerations and regression warnings
- CLI verification commands (curl)
- Interactive task management with verification lifecycle
"""

import streamlit as st
from typing import Dict, Any

from core.database import get_remediation_tasks, update_remediation_status
from ui.theme import (
    render_page_header,
    render_safe_html,
    get_tokens,
    get_verification_color,
)

# Comprehensive remediation templates for all supported configuration checks
REMEDIATION_GUIDES: Dict[str, Dict[str, Any]] = {
    "hsts_header": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "detected": "Missing or insufficient Strict-Transport-Security header.",
        "why_it_matters": "Enforces HTTPS connections and neutralizes SSL stripping downgrade attacks.",
        "what_to_change": "Configure reverse proxies to append Strict-Transport-Security with at least 1-year max-age.",
        "compatibility": "CRITICAL: Do not enable 'preload' or 'includeSubDomains' unless all subdomains and API endpoints support valid HTTPS certificates permanently. Preloading cannot be easily undone.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i strict-transport-security",
        "configs": {
            "Nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
            "Apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            "Caddy": "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            "Express (Node.js)": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
            "FastAPI / Python": "from starlette.middleware.base import BaseHTTPMiddleware\n\n@app.middleware(\"http\")\nasync def add_hsts(request, call_next):\n    response = await call_next(request)\n    response.headers[\"Strict-Transport-Security\"] = \"max-age=31536000; includeSubDomains; preload\"\n    return response",
        }
    },
    "content_security_policy": {
        "title": "Content-Security-Policy (CSP)",
        "detected": "Absent CSP or usage of permissive keywords ('unsafe-inline', 'unsafe-eval').",
        "why_it_matters": "Restricts sources of executable scripts, stylesheets, and objects, defending against Cross-Site Scripting (XSS).",
        "what_to_change": "Define a defense-in-depth policy. Start in report-only mode (Content-Security-Policy-Report-Only) before enforcement.",
        "compatibility": "Enforcing CSP can break existing inline scripts (<script>...</script>) or inline style attributes. Migrate scripts to static files or employ cryptographic nonces.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i content-security-policy",
        "configs": {
            "Nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\" always;",
            "Apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\"",
            "Caddy": "header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\"",
            "Express (Node.js)": "app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\"],\n    objectSrc: [\"'none'\"],\n    frameAncestors: [\"'none'\"]\n  }\n}));",
            "FastAPI / Python": "@app.middleware(\"http\")\nasync def add_csp(request, call_next):\n    response = await call_next(request)\n    response.headers[\"Content-Security-Policy\"] = \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"\n    return response",
        }
    },
    "x_frame_options": {
        "title": "Clickjacking Defense (X-Frame-Options / frame-ancestors)",
        "detected": "Neither X-Frame-Options nor CSP frame-ancestors directive was detected.",
        "why_it_matters": "Prevents third-party malicious websites from embedding your portal in an invisible iframe to hijack user clicks.",
        "what_to_change": "Configure reverse proxies to deny iframe embedding or restrict it to self.",
        "compatibility": "If your government website legitimately embeds widgets on partner agency sites, declare permitted origins in CSP frame-ancestors instead of DENY.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i x-frame-options",
        "configs": {
            "Nginx": "add_header X-Frame-Options \"DENY\" always;\n# Or for same-origin: add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "Apache": "Header always set X-Frame-Options \"DENY\"",
            "Caddy": "header X-Frame-Options \"DENY\"",
            "Express (Node.js)": "app.use(helmet.frameguard({ action: 'deny' }));",
            "FastAPI / Python": "response.headers[\"X-Frame-Options\"] = \"DENY\"",
        }
    },
    "x_content_type_options": {
        "title": "MIME-Sniffing Defense (X-Content-Type-Options)",
        "detected": "Header 'X-Content-Type-Options: nosniff' is absent.",
        "why_it_matters": "Prevents browsers from MIME-sniffing a response away from declared Content-Type, mitigating script execution via uploaded files.",
        "what_to_change": "Always set X-Content-Type-Options to 'nosniff'.",
        "compatibility": "Virtually zero compatibility risk; widely supported across all modern browsers.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i x-content-type-options",
        "configs": {
            "Nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "Apache": "Header always set X-Content-Type-Options \"nosniff\"",
            "Caddy": "header X-Content-Type-Options \"nosniff\"",
            "Express (Node.js)": "app.use(helmet.noSniff());",
            "FastAPI / Python": "response.headers[\"X-Content-Type-Options\"] = \"nosniff\"",
        }
    },
    "secure_cookies": {
        "title": "Cookie Security Flags (Secure, HttpOnly, SameSite)",
        "detected": "Cookies issued without Secure, HttpOnly, or SameSite flags.",
        "why_it_matters": "Protects session identifiers from network sniffing, XSS script theft, and cross-site request forgery.",
        "what_to_change": "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all Set-Cookie headers.",
        "compatibility": "Ensure application frontend scripts do not rely on reading session cookies directly via document.cookie.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i set-cookie",
        "configs": {
            "Nginx": "# If proxying: proxy_cookie_path / \"/; Secure; HttpOnly; SameSite=Lax\";",
            "Apache": "# Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
            "Express (Node.js)": "app.use(session({\n  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n}));",
            "Django (Python)": "SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Lax'\nCSRF_COOKIE_SECURE = True\nCSRF_COOKIE_HTTPONLY = True",
            "FastAPI (Python)": "response.set_cookie(key=\"session\", value=token, secure=True, httponly=True, samesite=\"lax\")",
        }
    },
    "server_disclosure": {
        "title": "Server Information Disclosure",
        "detected": "Server or X-Powered-By reveals verbose software versions or operating system info.",
        "why_it_matters": "Provides attackers with reconnaissance data to map known CVEs directly to your environment.",
        "what_to_change": "Disable or obfuscate server tokens and remove framework headers.",
        "compatibility": "No impact on clients or web functionality.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -Ei 'server|x-powered-by'",
        "configs": {
            "Nginx": "server_tokens off;",
            "Apache": "ServerTokens Prod\nServerSignature Off",
            "Express (Node.js)": "app.disable('x-powered-by');",
            "PHP (php.ini)": "expose_php = Off",
            "IIS": "<!-- web.config -->\n<httpProtocol><customHeaders><remove name=\"X-Powered-By\" /></customHeaders></httpProtocol>",
        }
    },
    "referrer_policy": {
        "title": "Referrer-Policy Header",
        "detected": "Absent or permissive Referrer-Policy header.",
        "why_it_matters": "Stops leakage of internal URL paths and sensitive query parameters to third-party domains.",
        "what_to_change": "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        "compatibility": "Safe for nearly all workflows.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i referrer-policy",
        "configs": {
            "Nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "Apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            "Caddy": "header Referrer-Policy \"strict-origin-when-cross-origin\"",
            "Express (Node.js)": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
            "FastAPI / Python": "response.headers[\"Referrer-Policy\"] = \"strict-origin-when-cross-origin\"",
        }
    },
    "permissions_policy": {
        "title": "Permissions-Policy Header",
        "detected": "Absent Permissions-Policy header.",
        "why_it_matters": "Governs browser hardware features (camera, mic, geolocation) preventing unauthorized access.",
        "what_to_change": "Disable unused browser hardware APIs by default.",
        "compatibility": "Review if your site legitimately utilizes geolocation or camera features before restricting.",
        "verification_cmd": "curl -sI https://your-domain.gov | grep -i permissions-policy",
        "configs": {
            "Nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
            "Apache": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"",
            "Caddy": "header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"",
            "Express (Node.js)": "app.use(helmet.permittedCrossDomainPolicies());",
            "FastAPI / Python": "response.headers[\"Permissions-Policy\"] = \"camera=(), microphone=(), geolocation=()\"",
        }
    }
}


def render_remediation_page() -> None:
    """Render the Remediation Knowledge Base and Task Tracker."""
    render_page_header(
        "Remediation",
        "Practical hardening playbooks, server configuration snippets, and task tracking",
    )
    tokens = get_tokens()

    render_safe_html(f"""
    <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-left: 4px solid {tokens['accent']}; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;">
        <div style="font-weight: 600; color: {tokens['accent']}; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.04em;">Safe Remediation Playbooks</div>
        <div style="font-size: 0.82rem; color: {tokens['text_secondary']}; line-height: 1.5; margin-top: 4px;">
            The configurations below are verified reference implementations. GOVNEXIS never modifies external servers automatically.
            Apply these changes in your staging environment first, test client interactions, and verify with a follow-up scan.
        </div>
    </div>
    """)

    tab_playbooks, tab_checklist = st.tabs(["Hardening Playbooks", "Remediation Tasks"])

    with tab_playbooks:
        selected_rule = st.selectbox(
            "Select Security Check Playbook",
            list(REMEDIATION_GUIDES.keys()),
            format_func=lambda k: REMEDIATION_GUIDES[k]["title"]
        )

        guide = REMEDIATION_GUIDES[selected_rule]

        st.subheader(guide['title'])
        col_info1, col_info2 = st.columns([1, 1])
        with col_info1:
            st.markdown(f"**What was detected:** {guide['detected']}")
            st.markdown(f"**Why it matters:** {guide['why_it_matters']}")
        with col_info2:
            st.markdown(f"**What to change:** {guide['what_to_change']}")
            st.markdown("**Verification Command:**")
            st.code(guide['verification_cmd'], language="bash")

        st.warning(f"Compatibility Considerations: {guide['compatibility']}")

        st.markdown("**Ready-to-Copy Server Configuration Snippets**")
        server_choice = st.radio(
            "Select Web Server / Application Framework",
            list(guide["configs"].keys()),
            horizontal=True
        )

        st.code(
            guide["configs"][server_choice],
            language="nginx" if "Nginx" in server_choice else "python" if "Python" in server_choice else "javascript" if "Node" in server_choice else "apache"
        )

    with tab_checklist:
        st.subheader("Actionable Remediation Tasks")
        st.caption("Track remediation progress. Only a subsequent scan can verify an issue as confirmed resolved.")

        tasks = get_remediation_tasks()
        if not tasks:
            st.info("No active remediation tasks. Run an audit scan to automatically generate remediation tasks.")
        else:
            for task in tasks:
                t_status = task["status"]
                t_color = get_verification_color(t_status)

                render_safe_html(f"""
                <div style="background: {tokens['surface']}; border: 1px solid {tokens['border']}; border-radius: 6px; padding: 14px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                        <div>
                            <span style="font-weight: 600; color: {tokens['text_primary']}; font-size: 0.95rem;">{task['title']}</span>
                            <span style="font-size: 0.8rem; color: {tokens['text_muted']}; margin-left: 8px;">Target: <code>{task['target_host']}</code></span>
                        </div>
                        <span style="font-weight: 600; color: {t_color}; font-size: 0.8rem; border: 1px solid {t_color}; padding: 2px 8px; border-radius: 4px;">
                            {t_status}
                        </span>
                    </div>
                    <div style="font-size: 0.8rem; color: {tokens['text_secondary']}; margin-top: 6px;">Notes: {task['notes'] or 'None'}</div>
                </div>
                """)

                c_sel, c_note, c_act = st.columns([1.5, 2.5, 1])
                with c_sel:
                    options = ["Open", "In Progress", "Fixed", "Verified"]
                    curr_idx = options.index(t_status) if t_status in options else 0
                    new_st = st.selectbox(
                        "Lifecycle",
                        options,
                        index=curr_idx,
                        key=f"task_sel_{task['id']}",
                        label_visibility="collapsed"
                    )
                with c_note:
                    note_text = st.text_input("Status Notes", value=task["notes"] or "", key=f"note_{task['id']}", label_visibility="collapsed", placeholder="Add progress notes...")
                with c_act:
                    if st.button("Update", key=f"up_btn_{task['id']}", use_container_width=True):
                        update_remediation_status(task["id"], new_st, note_text)
                        st.success("Updated.")
                        st.rerun()
