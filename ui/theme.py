"""Professional Theme System for GOVNEXIS.

Provides centralized design tokens for dark and light themes, a persistent
theme switcher, and reusable UI component helpers (badges, headers, cards).
All colours are defined here — no hardcoded colour values should appear in
individual page files.
"""

import os
import textwrap
import streamlit as st
from typing import Optional, Dict

from core.config import APP_NAME, APP_TAGLINE, APP_VERSION

THEME_DARK = "dark"
THEME_LIGHT = "light"

# ---------------------------------------------------------------------------
# Theme persistence (file-backed so it survives Streamlit reruns)
# ---------------------------------------------------------------------------
_THEME_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), ".theme_preference"
)


def get_current_theme() -> str:
    """Return the active theme name: ``'dark'`` or ``'light'``."""
    if "govnexis_theme" in st.session_state:
        return st.session_state["govnexis_theme"]
    if os.path.exists(_THEME_FILE):
        try:
            with open(_THEME_FILE, "r") as fh:
                pref = fh.read().strip()
                if pref in ("dark", "light"):
                    st.session_state["govnexis_theme"] = pref
                    return pref
        except OSError:
            pass
    st.session_state["govnexis_theme"] = "dark"
    return "dark"


def set_theme(theme: str) -> None:
    """Persist the chosen theme to session state and disk."""
    if theme not in ("dark", "light"):
        return
    st.session_state["govnexis_theme"] = theme
    try:
        with open(_THEME_FILE, "w") as fh:
            fh.write(theme)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Design tokens — every colour used in the application lives here
# ---------------------------------------------------------------------------
DARK_TOKENS: Dict[str, str] = {
    "bg":               "#171B22",
    "surface":          "#202630",
    "surface_elevated": "#272F3A",
    "text_primary":     "#F1F4F8",
    "text_secondary":   "#A8B2C0",
    "text_muted":       "#6B7280",
    "border":           "#394352",
    "accent":           "#36A779",
    "accent_hover":     "#2E9068",
    "accent_bg":        "rgba(54,167,121,0.12)",
    "accent_secondary": "#4D9DAD",
    "accent_teal":      "#4D9DAD",
    "warning":          "#D9A441",
    "warning_bg":       "rgba(217,164,65,0.12)",
    "error":            "#D76565",
    "error_bg":         "rgba(215,101,101,0.12)",
    "success":          "#36A779",
    "success_bg":       "rgba(54,167,121,0.12)",
    "sev_critical":     "#D76565",
    "sev_critical_bg":  "rgba(215,101,101,0.15)",
    "sev_high":         "#E08A4A",
    "sev_high_bg":      "rgba(224,138,74,0.15)",
    "sev_medium":       "#D9A441",
    "sev_medium_bg":    "rgba(217,164,65,0.15)",
    "sev_low":          "#4D9DAD",
    "sev_low_bg":       "rgba(77,157,173,0.15)",
    "sev_info":         "#7C8694",
    "sev_info_bg":      "rgba(124,134,148,0.15)",
    "chart_grid":       "rgba(57,67,82,0.5)",
    "chart_text":       "#A8B2C0",
}

LIGHT_TOKENS: Dict[str, str] = {
    "bg":               "#F4F6F8",
    "surface":          "#FFFFFF",
    "surface_elevated": "#FFFFFF",
    "text_primary":     "#202833",
    "text_secondary":   "#5E6875",
    "text_muted":       "#9CA3AF",
    "border":           "#DCE2E8",
    "accent":           "#187A56",
    "accent_hover":     "#15694A",
    "accent_bg":        "rgba(24,122,86,0.08)",
    "accent_secondary": "#267787",
    "accent_teal":      "#267787",
    "warning":          "#B8860B",
    "warning_bg":       "rgba(184,134,11,0.08)",
    "error":            "#C0392B",
    "error_bg":         "rgba(192,57,43,0.08)",
    "success":          "#187A56",
    "success_bg":       "rgba(24,122,86,0.08)",
    "sev_critical":     "#C0392B",
    "sev_critical_bg":  "rgba(192,57,43,0.10)",
    "sev_high":         "#D35400",
    "sev_high_bg":      "rgba(211,84,0,0.10)",
    "sev_medium":       "#B8860B",
    "sev_medium_bg":    "rgba(184,134,11,0.10)",
    "sev_low":          "#267787",
    "sev_low_bg":       "rgba(38,119,135,0.10)",
    "sev_info":         "#6B7280",
    "sev_info_bg":      "rgba(107,114,128,0.10)",
    "chart_grid":       "rgba(220,226,232,0.8)",
    "chart_text":       "#5E6875",
}


def get_tokens() -> Dict[str, str]:
    """Return the design-token dictionary for the active theme."""
    return DARK_TOKENS if get_current_theme() == "dark" else LIGHT_TOKENS


# ---------------------------------------------------------------------------
# Logo SVG — clean professional shield with checkmark
# ---------------------------------------------------------------------------
def get_logo_svg(size: int = 32) -> str:
    """Return the GOVNEXIS shield logo sized to *size* px."""
    t = get_tokens()
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 100 100" '
        f'fill="none" xmlns="http://www.w3.org/2000/svg">'
        f'<path d="M50 8 L85 25 V52 C85 74 50 92 50 92 '
        f'C50 92 15 74 15 52 V25 L50 8 Z" '
        f'stroke="{t["accent"]}" stroke-width="4" fill="{t["surface_elevated"]}" />'
        f'<path d="M50 20 L75 33 V52 C75 67 50 80 50 80 '
        f'C50 80 25 67 25 52 V33 L50 20 Z" '
        f'stroke="{t["border"]}" stroke-width="1.5" fill="none" />'
        f'<path d="M40 52 L47 59 L62 42" stroke="{t["accent"]}" '
        f'stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none" />'
        f'</svg>'
    )


# Keep module-level LOGO_SVG for backward compatibility (app.py import)
LOGO_SVG = ""  # Populated at runtime via get_logo_svg()


# ---------------------------------------------------------------------------
# CSS generation
# ---------------------------------------------------------------------------
def _build_css(t: Dict[str, str]) -> str:
    """Build the full CSS stylesheet from a token dictionary."""
    return f"""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* === Base === */
.stApp {{
    background-color: {t['bg']} !important;
    color: {t['text_primary']} !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
}}
h1,h2,h3,h4,h5,h6 {{
    font-family: 'Inter', sans-serif !important;
    color: {t['text_primary']} !important;
    font-weight: 600 !important;
}}
code, pre {{ font-family: 'JetBrains Mono', Consolas, monospace !important; }}
a {{ color: {t['accent_secondary']} !important; }}
hr {{ border-color: {t['border']} !important; }}

/* === Sidebar === */
section[data-testid="stSidebar"] {{
    background-color: {t['surface']} !important;
    border-right: 1px solid {t['border']} !important;
    box-shadow: none !important;
}}
section[data-testid="stSidebar"] .stRadio > div {{ gap: 2px !important; }}
section[data-testid="stSidebar"] label {{
    font-family: 'Inter', sans-serif !important;
    font-size: 0.875rem !important;
    font-weight: 500 !important;
    color: {t['text_secondary']} !important;
    transition: color 0.15s ease !important;
}}
section[data-testid="stSidebar"] label:hover {{
    color: {t['text_primary']} !important;
    text-shadow: none !important;
}}

/* === Buttons === */
.stButton > button {{
    font-family: 'Inter', sans-serif !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
    border: 1px solid {t['border']} !important;
    background: {t['surface_elevated']} !important;
    color: {t['text_primary']} !important;
    transition: all 0.15s ease !important;
    text-transform: none !important;
    letter-spacing: normal !important;
    box-shadow: none !important;
}}
.stButton > button:hover {{
    border-color: {t['accent']} !important;
    background: {t['accent_bg']} !important;
    transform: none !important;
    box-shadow: none !important;
}}
.stButton > button[kind="primary"] {{
    background: {t['accent']} !important;
    border-color: {t['accent']} !important;
    color: #ffffff !important;
}}
.stButton > button[kind="primary"]:hover {{
    background: {t['accent_hover']} !important;
    border-color: {t['accent_hover']} !important;
    box-shadow: none !important;
}}
.stDownloadButton > button {{
    font-family: 'Inter', sans-serif !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
    border: 1px solid {t['border']} !important;
    background: {t['surface_elevated']} !important;
    color: {t['text_primary']} !important;
    box-shadow: none !important;
}}
.stDownloadButton > button:hover {{
    border-color: {t['accent']} !important;
}}

/* === Inputs === */
.stTextInput input, .stTextArea textarea {{
    background-color: {t['surface']} !important;
    border: 1px solid {t['border']} !important;
    color: {t['text_primary']} !important;
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
}}
.stTextInput input:focus, .stTextArea textarea:focus {{
    border-color: {t['accent']} !important;
    box-shadow: 0 0 0 1px {t['accent']} !important;
}}

/* === Tabs === */
.stTabs [data-baseweb="tab-list"] {{
    gap: 0 !important;
    border-bottom: 1px solid {t['border']} !important;
}}
.stTabs [data-baseweb="tab"] {{
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.85rem !important;
    color: {t['text_secondary']} !important;
    background: transparent !important;
    padding: 8px 16px !important;
}}
.stTabs [aria-selected="true"] {{
    color: {t['accent']} !important;
}}

/* === Expanders === */
[data-testid="stExpander"] {{
    background-color: {t['surface']} !important;
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
    box-shadow: none !important;
}}
[data-testid="stExpander"] summary {{
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    color: {t['text_primary']} !important;
}}

/* === Dataframes === */
[data-testid="stDataFrame"] {{
    border: 1px solid {t['border']} !important;
    border-radius: 6px !important;
}}

/* === Alerts === */
[data-testid="stAlert"] {{
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
}}

/* === Custom component classes === */

/* Metric card */
.gn-metric {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-radius: 8px;
    padding: 16px 20px;
    transition: border-color 0.15s ease;
}}
.gn-metric:hover {{ border-color: {t['accent']}; }}
.gn-metric-label {{
    font-size: 0.7rem; font-weight: 600; color: {t['text_muted']};
    text-transform: uppercase; letter-spacing: 0.04em;
    font-family: 'Inter', sans-serif;
}}
.gn-metric-value {{
    font-size: 1.75rem; font-weight: 700; color: {t['text_primary']};
    margin: 4px 0; line-height: 1.2; font-family: 'Inter', sans-serif;
}}
.gn-metric-sub {{
    font-size: 0.8rem; color: {t['text_secondary']};
    font-family: 'Inter', sans-serif;
}}

/* Page header */
.gn-page-header {{
    margin-bottom: 24px; padding-bottom: 16px;
    border-bottom: 1px solid {t['border']};
}}
.gn-page-title {{
    font-size: 1.25rem; font-weight: 700; color: {t['text_primary']};
    margin: 0; line-height: 1.3; font-family: 'Inter', sans-serif;
}}
.gn-page-desc {{
    font-size: 0.85rem; color: {t['text_secondary']};
    margin-top: 4px; font-family: 'Inter', sans-serif;
}}

/* Info banner */
.gn-banner {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-left: 3px solid {t['accent']};
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 20px;
}}
.gn-banner-title {{
    font-weight: 600; font-size: 0.85rem; color: {t['accent']};
    font-family: 'Inter', sans-serif;
}}
.gn-banner-text {{
    font-size: 0.8rem; color: {t['text_secondary']};
    margin-top: 4px; line-height: 1.5; font-family: 'Inter', sans-serif;
}}

/* Status badges */
.gn-badge {{
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600; letter-spacing: 0.02em;
    font-family: 'Inter', sans-serif;
}}
.gn-badge-pass {{
    background: {t['success_bg']}; color: {t['success']};
    border: 1px solid {t['success']};
}}
.gn-badge-fail {{
    background: {t['error_bg']}; color: {t['error']};
    border: 1px solid {t['error']};
}}
.gn-badge-warning {{
    background: {t['warning_bg']}; color: {t['warning']};
    border: 1px solid {t['warning']};
}}
.gn-badge-na {{
    background: {t['sev_info_bg']}; color: {t['sev_info']};
    border: 1px solid {t['sev_info']};
}}

/* Severity badges */
.gn-sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.7rem; font-weight: 700; font-family: 'Inter', sans-serif; }}
.gn-sev-critical {{ background: {t['sev_critical_bg']}; color: {t['sev_critical']}; border: 1px solid {t['sev_critical']}; }}
.gn-sev-high     {{ background: {t['sev_high_bg']};     color: {t['sev_high']};     border: 1px solid {t['sev_high']}; }}
.gn-sev-medium   {{ background: {t['sev_medium_bg']};   color: {t['sev_medium']};   border: 1px solid {t['sev_medium']}; }}
.gn-sev-low      {{ background: {t['sev_low_bg']};      color: {t['sev_low']};      border: 1px solid {t['sev_low']}; }}
.gn-sev-info     {{ background: {t['sev_info_bg']};     color: {t['sev_info']};     border: 1px solid {t['sev_info']}; }}

/* Demo banner */
.gn-demo-banner {{
    background: {t['accent_bg']};
    border: 1px solid {t['accent']};
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 20px;
}}

/* Sidebar brand */
.gn-sidebar-brand {{
    display: flex; align-items: center; gap: 10px;
    padding: 4px 0 14px 0;
    border-bottom: 1px solid {t['border']};
    margin-bottom: 12px;
}}
.gn-sidebar-wordmark {{
    font-family: 'Inter', sans-serif; font-size: 1.1rem;
    font-weight: 700; color: {t['text_primary']}; letter-spacing: 0.01em;
}}
.gn-sidebar-wordmark span {{ color: {t['accent']}; }}
.gn-sidebar-subtitle {{
    font-family: 'Inter', sans-serif; font-size: 0.68rem;
    color: {t['text_muted']};
}}

/* Compliance box */
.gn-compliance {{
    background: {t['surface_elevated']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 10px 12px; margin-top: 8px;
}}
.gn-compliance-title {{
    font-family: 'Inter', sans-serif; font-size: 0.68rem;
    font-weight: 600; color: {t['accent']};
    text-transform: uppercase; letter-spacing: 0.04em;
}}
.gn-compliance-list {{
    font-family: 'Inter', sans-serif; font-size: 0.68rem;
    color: {t['text_secondary']}; margin-top: 4px; line-height: 1.5;
}}

/* Finding row */
.gn-finding-row {{
    background: {t['surface']}; border: 1px solid {t['border']};
    border-radius: 6px; padding: 12px 16px; margin-bottom: 8px;
    display: flex; justify-content: space-between; align-items: center;
}}
.gn-finding-title {{
    font-weight: 600; color: {t['text_primary']}; font-size: 0.9rem;
    font-family: 'Inter', sans-serif;
}}
.gn-finding-meta {{
    font-size: 0.75rem; color: {t['text_muted']};
    font-family: 'JetBrains Mono', monospace;
}}

/* Tracking status */
.gn-status-box {{
    background: {t['surface_elevated']}; border: 1px solid {t['border']};
    border-radius: 6px; padding: 10px 12px; margin-bottom: 10px;
}}

/* Score box */
.gn-score-box {{
    background: {t['surface']}; border-radius: 8px;
    padding: 20px; text-align: center;
}}

/* Verification delta */
.gn-delta-card {{
    background: {t['surface']}; border: 1px solid {t['border']};
    border-radius: 8px; padding: 16px; text-align: center;
}}
</style>"""


# ---------------------------------------------------------------------------
# Safe HTML renderer
# ---------------------------------------------------------------------------
def render_safe_html(html_str: str) -> None:
    """Render HTML content safely, avoiding Markdown pre-block interpretation."""
    clean = textwrap.dedent(html_str).strip()
    if hasattr(st, "html"):
        st.html(clean)
    else:
        no_indent = "\n".join(line.lstrip() for line in clean.splitlines())
        st.markdown(no_indent, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Apply theme — call once at app startup
# ---------------------------------------------------------------------------
def apply_theme() -> None:
    """Inject the active theme's CSS into the current Streamlit page."""
    tokens = get_tokens()
    render_safe_html(_build_css(tokens))


# ---------------------------------------------------------------------------
# Reusable UI component helpers
# ---------------------------------------------------------------------------

def render_page_header(title: str, description: str = "") -> None:
    """Render a consistent page header with title and optional description."""
    desc_html = f'<div class="gn-page-desc">{description}</div>' if description else ""
    render_safe_html(f"""
    <div class="gn-page-header">
        <div class="gn-page-title">{title}</div>
        {desc_html}
    </div>
    """)


def render_brand_header(subtitle: Optional[str] = None) -> None:
    """Render a page header with the GOVNEXIS title. Replaces the old flashy header."""
    sub_text = subtitle or APP_TAGLINE
    render_page_header(f"GOVNEXIS — {sub_text}")


def render_sidebar_brand() -> None:
    """Render a compact sidebar branding area with logo and wordmark."""
    logo = get_logo_svg(28)
    render_safe_html(f"""
    <div class="gn-sidebar-brand">
        {logo}
        <div>
            <div class="gn-sidebar-wordmark">GOV<span>NEXIS</span></div>
            <div class="gn-sidebar-subtitle">Security Audit Platform</div>
        </div>
    </div>
    """)


def render_sidebar_compliance() -> None:
    """Render the sidebar compliance reference block."""
    render_safe_html("""
    <div class="gn-compliance">
        <div class="gn-compliance-title">Reference Standards</div>
        <div class="gn-compliance-list">
            CISA BOD 18-01<br>
            NIST SP 800-52r2<br>
            OWASP Secure Headers
        </div>
    </div>
    """)


def render_demo_banner() -> None:
    """Render an informational notice that local demo sandbox is active."""
    t = get_tokens()
    render_safe_html(f"""
    <div class="gn-demo-banner">
        <div style="font-weight:600; font-size:0.85rem; color:{t['accent']}; font-family:'Inter',sans-serif;">
            Isolated Local Sandbox Environment
        </div>
        <div style="font-size:0.8rem; color:{t['text_secondary']}; margin-top:4px; font-family:'Inter',sans-serif;">
            Target is restricted to <code>127.0.0.1:8765</code>. No external network traffic is generated.
        </div>
    </div>
    """)


def render_info_banner(title: str, text: str, border_color: Optional[str] = None) -> None:
    """Render a contextual information banner."""
    t = get_tokens()
    color = border_color or t["accent"]
    render_safe_html(f"""
    <div class="gn-banner" style="border-left-color:{color};">
        <div class="gn-banner-title" style="color:{color};">{title}</div>
        <div class="gn-banner-text">{text}</div>
    </div>
    """)


def render_metric_card_html(
    label: str,
    value: str,
    subtitle: str = "",
    value_color: Optional[str] = None,
    delta_color: Optional[str] = None,
) -> str:
    """Return the HTML string for a metric card (caller wraps in column)."""
    color = value_color or delta_color
    val_style = f' style="color:{color};"' if color else ""
    sub = f'<div class="gn-metric-sub">{subtitle}</div>' if subtitle else ""
    return f"""
    <div class="gn-metric">
        <div class="gn-metric-label">{label}</div>
        <div class="gn-metric-value"{val_style}>{value}</div>
        {sub}
    </div>
    """


# ---------------------------------------------------------------------------
# Badge helpers
# ---------------------------------------------------------------------------

def get_status_badge_html(status: str) -> str:
    """Return an HTML badge for PASS / FAIL / WARNING / NOT ASSESSED."""
    status_upper = status.upper().strip()
    if status_upper == "PASS":
        return '<span class="gn-badge gn-badge-pass">PASS</span>'
    elif status_upper == "FAIL":
        return '<span class="gn-badge gn-badge-fail">FAIL</span>'
    elif status_upper == "WARNING":
        return '<span class="gn-badge gn-badge-warning">WARNING</span>'
    else:
        return '<span class="gn-badge gn-badge-na">NOT ASSESSED</span>'


def get_severity_badge_html(severity: str) -> str:
    """Return an HTML badge for the given finding severity level."""
    s = severity.lower().strip()
    if s == "critical":
        return '<span class="gn-sev gn-sev-critical">CRITICAL</span>'
    elif s == "high":
        return '<span class="gn-sev gn-sev-high">HIGH</span>'
    elif s == "medium":
        return '<span class="gn-sev gn-sev-medium">MEDIUM</span>'
    elif s == "low":
        return '<span class="gn-sev gn-sev-low">LOW</span>'
    else:
        return '<span class="gn-sev gn-sev-info">INFO</span>'


def get_score_color(score: int) -> str:
    """Return the appropriate accent colour for a numeric security score."""
    t = get_tokens()
    if score >= 80:
        return t["success"]
    elif score >= 60:
        return t["warning"]
    else:
        return t["error"]


def get_verification_color(status: str) -> str:
    """Return a colour for finding verification lifecycle status."""
    t = get_tokens()
    status_lower = status.lower().strip()
    if status_lower == "verified":
        return t["success"]
    elif status_lower == "fixed":
        return t["accent_secondary"]
    elif status_lower == "in progress":
        return t["warning"]
    else:
        return t["error"]


# ---------------------------------------------------------------------------
# Plotly chart theme helper
# ---------------------------------------------------------------------------

def get_plotly_layout_defaults() -> dict:
    """Return common Plotly layout kwargs matching the active theme."""
    t = get_tokens()
    return {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"color": t["chart_text"], "family": "Inter, sans-serif"},
    }


def get_cvss_badge_html(score: Optional[float] = None, severity: Optional[str] = None, status: Optional[str] = None) -> str:
    """Return an HTML badge for CVSS v3.0 score and severity."""
    if status == "NOT_SCORED" or (score is None and (severity is None or severity == "Not Scored")):
        return '<span class="gn-sev gn-sev-info">NOT SCORED</span>'
    
    s = (severity or "").lower().strip()
    if not s and score is not None:
        if score == 0.0:
            s = "none"
        elif score < 4.0:
            s = "low"
        elif score < 7.0:
            s = "medium"
        elif score < 9.0:
            s = "high"
        else:
            s = "critical"

    if s == "critical":
        val_str = f"{score:.1f}" if score is not None else "9.0+"
        return f'<span class="gn-sev gn-sev-critical">CVSS {val_str} CRITICAL</span>'
    elif s == "high":
        val_str = f"{score:.1f}" if score is not None else "7.0+"
        return f'<span class="gn-sev gn-sev-high">CVSS {val_str} HIGH</span>'
    elif s == "medium":
        val_str = f"{score:.1f}" if score is not None else "4.0+"
        return f'<span class="gn-sev gn-sev-medium">CVSS {val_str} MEDIUM</span>'
    elif s == "low":
        val_str = f"{score:.1f}" if score is not None else "0.1+"
        return f'<span class="gn-sev gn-sev-low">CVSS {val_str} LOW</span>'
    elif s == "none" or score == 0.0:
        return '<span class="gn-sev gn-sev-info" style="border-color:#36A779; color:#36A779;">CVSS 0.0 NONE</span>'
    else:
        return '<span class="gn-sev gn-sev-info">NOT SCORED</span>'


def get_cvss_color(score: Optional[float]) -> str:
    """Return the theme color corresponding to a CVSS base score."""
    t = get_tokens()
    if score is None:
        return t["text_muted"]
    if score >= 9.0:
        return t["sev_critical"]
    elif score >= 7.0:
        return t["sev_high"]
    elif score >= 4.0:
        return t["sev_medium"]
    elif score > 0.0:
        return t["sev_low"]
    else:
        return t["success"]


def get_cvss_color_map() -> dict:
    """Return Plotly color map for CVSS v3.0 severity distribution."""
    t = get_tokens()
    return {
        "Critical":   t["sev_critical"],
        "High":       t["sev_high"],
        "Medium":     t["sev_medium"],
        "Low":        t["sev_low"],
        "None":       t["success"],
        "Not Scored": t["sev_info"],
    }


def get_severity_color_map() -> dict:
    """Return a Plotly-compatible severity→colour mapping for the active theme."""
    t = get_tokens()
    return {
        "Critical":      t["sev_critical"],
        "High":          t["sev_high"],
        "Medium":        t["sev_medium"],
        "Low":           t["sev_low"],
        "Informational": t["sev_info"],
    }
