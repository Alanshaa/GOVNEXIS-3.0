"""Overview dashboard for GOVNEXIS with official CVSS v3.0 Risk Matrix.

Displays:
- Summary KPI cards: Total Scans, Unique Targets, Configuration Compliance, and Max CVSS Base Score
- Official CVSS v3.0 Risk Severity Matrix (donut distribution across official brackets)
- Category breakdown (horizontal bar chart)
- Chronological scan score progression
- Recent scan activity with CVSS scores and compliance grades
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any

from core.database import get_scan_trends, get_all_scans, seed_demo_history
from ui.theme import (
    render_page_header,
    render_metric_card_html,
    render_safe_html,
    get_tokens,
    get_score_color,
    get_cvss_color,
    get_cvss_color_map,
    get_plotly_layout_defaults,
)


def render_overview_page() -> None:
    """Render the executive overview dashboard with CVSS v3.0 Risk Matrix."""
    render_page_header(
        "Overview",
        "Executive cybersecurity posture, CVSS v3.0 vulnerability matrix, and compliance trends",
    )
    t = get_tokens()

    # Load aggregated data from database
    trends = get_scan_trends()

    # Handle completely empty state
    if trends["total_scans"] == 0:
        st.info(
            "No scan data yet. Run a scan from **New Scan** or try the "
            "**Demo Lab** to see results here."
        )
        return

    # ---- KPI cards (CVSS v3.0 Focus) ----
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        render_safe_html(render_metric_card_html(
            "Total Scans", str(trends["total_scans"]), "Stored audit records"
        ))
    with col2:
        render_safe_html(render_metric_card_html(
            "Unique Targets", str(trends["unique_targets"]), "Distinct hostnames audited"
        ))
    with col3:
        cvss_counts = trends.get("cvss_severity_counts", {})
        crit_high = cvss_counts.get("Critical", 0) + cvss_counts.get("High", 0)
        crit_color = t["sev_critical"] if crit_high > 0 else t["success"]
        render_safe_html(f"""
        <div class="gn-metric">
            <div class="gn-metric-label">High & Critical Risks</div>
            <div class="gn-metric-value" style="color:{crit_color};">
                {crit_high}
            </div>
            <div class="gn-metric-sub">Actionable CVSS &ge; 7.0 findings</div>
        </div>
        """)
    with col4:
        max_cvss = trends.get("max_cvss_score", 0.0)
        cvss_color = get_cvss_color(max_cvss if max_cvss > 0 else None)
        cvss_label = (
            "CRITICAL" if max_cvss >= 9.0 else
            "HIGH" if max_cvss >= 7.0 else
            "MEDIUM" if max_cvss >= 4.0 else
            "LOW" if max_cvss > 0.0 else "NONE"
        )
        render_safe_html(f"""
        <div class="gn-metric">
            <div class="gn-metric-label">Max CVSS v3.0 Score</div>
            <div class="gn-metric-value" style="color:{cvss_color};">
                {max_cvss:.1f}<span style="font-size:0.85rem; color:{t['text_muted']};"> ({cvss_label})</span>
            </div>
            <div class="gn-metric-sub">Peak vulnerability severity</div>
        </div>
        """)

    st.markdown("")

    # ---- Row 1: CVSS v3.0 Risk Matrix + Category breakdown ----
    chart_layout = get_plotly_layout_defaults()
    cvss_colors = get_cvss_color_map()

    donut_col, bar_col = st.columns(2)

    with donut_col:
        st.markdown("##### CVSS v3.0 Vulnerability Severity Matrix")
        cvss_counts = trends.get("cvss_severity_counts", {})
        cvss_df = pd.DataFrame([
            {"Severity": sev, "Count": cvss_counts.get(sev, 0)}
            for sev in ("Critical", "High", "Medium", "Low", "Not Scored")
            if cvss_counts.get(sev, 0) > 0 or sev in ("Critical", "High", "Medium", "Low")
        ])
        total_findings = sum(cvss_counts.get(s, 0) for s in ("Critical", "High", "Medium", "Low", "Not Scored"))

        if total_findings > 0:
            fig_sev = px.pie(
                cvss_df, names="Severity", values="Count", hole=0.55,
                color="Severity", color_discrete_map=cvss_colors,
            )
            fig_sev.update_traces(
                textposition="inside", textinfo="percent+label",
                marker=dict(line=dict(color=t["bg"], width=2)),
            )
            fig_sev.update_layout(
                **chart_layout,
                margin=dict(t=10, b=10, l=10, r=10),
                legend=dict(
                    orientation="h", yanchor="bottom", y=-0.2,
                    xanchor="center", x=0.5, font=dict(size=11),
                ),
                height=280,
                annotations=[{
                    "text": f"<b>{total_findings}</b><br><span style='font-size:10px;color:{t['text_muted']};'>FINDINGS</span>",
                    "x": 0.5, "y": 0.5,
                    "font": {"size": 16, "color": t["text_primary"]},
                    "showarrow": False,
                }],
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No active findings detected.")

    with bar_col:
        st.markdown("##### Findings by Security Category")
        cat_counts = trends["category_counts"]
        if cat_counts:
            cat_df = pd.DataFrame([
                {"Category": cat, "Findings": count}
                for cat, count in cat_counts.items()
            ]).head(8)
            fig_cat = px.bar(
                cat_df, x="Findings", y="Category", orientation="h",
                color_discrete_sequence=[t["accent"]],
            )
            fig_cat.update_layout(
                **chart_layout,
                margin=dict(t=10, b=10, l=10, r=10),
                yaxis=dict(categoryorder="total ascending",
                           tickfont=dict(size=11, color=t["chart_text"])),
                xaxis=dict(showgrid=True, gridcolor=t["chart_grid"]),
                height=280,
                showlegend=False,
            )
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info("No categorized findings.")

    # Methodology Explanatory Callout
    render_safe_html(f"""
    <div style="background: {t['surface']}; border: 1px solid {t['border']}; border-left: 4px solid {t['accent']}; padding: 12px 16px; border-radius: 6px; margin: 10px 0 20px 0;">
        <span style="font-weight: 600; color: {t['text_primary']}; font-size: 0.84rem;">Official CVSS v3.0 Vulnerability Risk Matrix:</span>
        <span style="font-size: 0.82rem; color: {t['text_secondary']}; margin-left: 6px; line-height: 1.5;">
            Risk severity is calculated strictly using official FIRST CVSS v3.0 base metric equations (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability).
            Defense-in-depth configurations without verified exploit chains remain "Not Scored" to eliminate speculative severity inflation.
        </span>
    </div>
    """)

    # ---- Row 2: Score progression timeline ----
    activity = trends.get("activity_over_time", [])
    if len(activity) > 1:
        st.markdown("##### Audit Activity Timeline")
        act_df = pd.DataFrame(activity)
        fig_time = px.line(
            act_df, x="date", y="count",
            markers=True,
            labels={"date": "Audit Date", "count": "Audit Scans Executed"},
        )
        fig_time.update_traces(
            line=dict(color=t["accent"], width=2.5),
            marker=dict(size=6, color=t["accent"]),
        )
        fig_time.update_layout(
            **chart_layout,
            margin=dict(t=10, b=10, l=10, r=10),
            yaxis=dict(showgrid=True, gridcolor=t["chart_grid"]),
            xaxis=dict(showgrid=False),
            height=220,
        )
        st.plotly_chart(fig_time, use_container_width=True)

    # ---- Row 3: Recent scan activity table ----
    st.markdown("##### Recent Audits")
    recent_scans = get_all_scans(limit=5)
    if recent_scans:
        import json
        rows = []
        for s in recent_scans:
            cvss_score = 0.0
            try:
                raw_data = json.loads(s.get("raw_json") or "{}")
                cvss_score = raw_data.get("score_report", {}).get("max_cvss_score", 0.0)
            except Exception:
                cvss_score = 0.0

            cvss_sev = (
                "CRITICAL" if cvss_score >= 9.0 else
                "HIGH" if cvss_score >= 7.0 else
                "MEDIUM" if cvss_score >= 4.0 else
                "LOW" if cvss_score > 0.0 else "NONE"
            )
            rows.append({
                "Target Host": s["hostname"],
                "Timestamp": s["timestamp"][:19],
                "CVSS v3.0 Base Score": f"{cvss_score:.1f}",
                "CVSS Severity": cvss_sev,
                "Passed": s["passed_checks"],
                "Failed": s["failed_checks"],
                "Warnings": s["warning_checks"],
                "Scan Type": "Sandbox Demo" if s["is_demo"] else "Production",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
