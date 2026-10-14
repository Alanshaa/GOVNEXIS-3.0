"""Transparent Security Scoring Engine for GOVNEXIS.

Implements an explainable, deterministic scoring methodology grounded in
observed configuration checks:
- Configuration Compliance Score (0–100) based on weighted security standards (CISA BOD 18-01 / NIST SP 800-52).
- CVSS v3.0 Vulnerability Severity Matrix integration (Base scores 0.0–10.0 and official ratings).
- Full audit breakdown explaining points awarded, penalties, and excluded checks.
- Clear distinction between CVSS vulnerability severity and configuration compliance.
"""

from typing import List, Dict, Any, Optional
from core.config import (
    CHECK_WEIGHTS, STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH
)
from core.security_checks import FindingRecord


class ScoreReport:
    """Detailed explainable security score breakdown with CVSS v3.0 risk summary."""

    def __init__(
        self,
        final_score: int,
        letter_grade: str,
        total_possible_points: int,
        earned_points: float,
        breakdown: List[Dict[str, Any]],
        critical_high_count: int,
        summary_statement: str,
        methodology_notes: str,
        max_cvss_score: Optional[float] = None,
        cvss_severity_distribution: Optional[Dict[str, int]] = None,
        scored_vulnerabilities_count: int = 0,
        unscored_findings_count: int = 0,
    ):
        self.final_score = final_score
        self.letter_grade = letter_grade
        self.total_possible_points = total_possible_points
        self.earned_points = earned_points
        self.breakdown = breakdown
        self.critical_high_count = critical_high_count
        self.summary_statement = summary_statement
        self.methodology_notes = methodology_notes
        self.max_cvss_score = max_cvss_score
        self.cvss_severity_distribution = cvss_severity_distribution or {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Not Scored": 0
        }
        self.scored_vulnerabilities_count = scored_vulnerabilities_count
        self.unscored_findings_count = unscored_findings_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_score": self.final_score,
            "letter_grade": self.letter_grade,
            "total_possible_points": self.total_possible_points,
            "earned_points": round(self.earned_points, 1),
            "breakdown": self.breakdown,
            "critical_high_count": self.critical_high_count,
            "summary_statement": self.summary_statement,
            "methodology_notes": self.methodology_notes,
            "max_cvss_score": self.max_cvss_score,
            "cvss_severity_distribution": self.cvss_severity_distribution,
            "scored_vulnerabilities_count": self.scored_vulnerabilities_count,
            "unscored_findings_count": self.unscored_findings_count,
        }


def calculate_grade(score: int, critical_high_count: int) -> str:
    """Calculate transparent letter grade reflecting both score and critical findings."""
    # Safety rule: If any CRITICAL finding exists, grade cannot exceed C
    if critical_high_count > 0 and score >= 80:
        if any(c == "Critical" for c in [critical_high_count]):
            return "B-"
    if score >= 90:
        return "A+" if score >= 95 else "A"
    elif score >= 80:
        return "B+" if score >= 85 else "B"
    elif score >= 70:
        return "C+" if score >= 75 else "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def compute_security_score(findings: List[FindingRecord]) -> ScoreReport:
    """Calculate the transparent security configuration score and CVSS summary from findings."""
    total_assessed_possible = 0
    total_earned = 0.0
    breakdown: List[Dict[str, Any]] = []
    critical_high_count = 0

    findings_by_id = {f.check_id: f for f in findings}

    for check_id, meta in CHECK_WEIGHTS.items():
        weight = meta["weight"]
        finding = findings_by_id.get(check_id)

        if not finding:
            status = STATUS_NOT_ASSESSED
            earned = 0.0
            explanation = "Check was not evaluated in this scan pass."
        else:
            status = finding.status
            if finding.severity in (SEV_CRITICAL, SEV_HIGH) and status in (STATUS_FAIL, STATUS_WARNING):
                critical_high_count += 1

            if status == STATUS_PASS:
                earned = float(weight)
                explanation = f"Passed full standard (+{weight} pts)."
            elif status == STATUS_WARNING:
                # 50% partial credit for warning/contextual concern
                earned = float(weight) * 0.5
                explanation = f"Partial configuration (+{earned:.1f} pts, 50% penalty applied: {finding.evidence[:80]})."
            elif status == STATUS_FAIL:
                earned = 0.0
                explanation = f"Failed check (-{weight} pts: {finding.evidence[:80]})."
            else:  # NOT_ASSESSED
                earned = 0.0
                explanation = "Excluded from scoring denominator (Not Assessed / Not Applicable)."

        if status != STATUS_NOT_ASSESSED:
            total_assessed_possible += weight
            total_earned += earned

        breakdown.append({
            "check_id": check_id,
            "title": meta["title"],
            "category": meta["category"],
            "status": status,
            "weight": weight,
            "points_earned": round(earned, 1),
            "explanation": explanation,
        })

    # Normalized configuration compliance score out of 100 based on evaluated checks
    if total_assessed_possible > 0:
        normalized_score = int(round((total_earned / total_assessed_possible) * 100))
    else:
        normalized_score = 0

    normalized_score = max(0, min(100, normalized_score))
    letter_grade = calculate_grade(normalized_score, critical_high_count)

    # Calculate CVSS v3.0 metrics across findings
    cvss_distribution: Dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Not Scored": 0
    }
    max_cvss: float = 0.0
    has_scored_cvss = False
    scored_count = 0
    unscored_count = 0

    for f in findings:
        cvss_data = getattr(f, "cvss", None)
        if cvss_data:
            sev = cvss_data.severity
            cvss_distribution[sev] = cvss_distribution.get(sev, 0) + 1
            if cvss_data.base_score is not None and cvss_data.base_score > 0.0:
                has_scored_cvss = True
                scored_count += 1
                if cvss_data.base_score > max_cvss:
                    max_cvss = cvss_data.base_score
            elif cvss_data.status in ("NOT_SCORED", "Not Scored") or cvss_data.base_score is None:
                unscored_count += 1
        else:
            cvss_distribution["Not Scored"] += 1
            unscored_count += 1

    max_cvss_score = max_cvss if has_scored_cvss else 0.0

    summary = (
        f"Overall Configuration Compliance Score: {normalized_score}/100 (Grade {letter_grade}). "
        f"Awarded {total_earned:.1f} of {total_assessed_possible} assessed points across {len(breakdown)} rules. "
        f"Max CVSS v3.0 Base Score: {max_cvss_score:.1f} ({scored_count} scored vulnerabilities, {unscored_count} defense-in-depth findings)."
    )
    if critical_high_count > 0:
        summary += f" Attention: {critical_high_count} Critical or High priority gap(s) require remediation."

    methodology = (
        "Methodology: Configuration Compliance (0-100) measures alignment with CISA BOD 18-01, "
        "NIST SP 800-52r2, and OWASP recommendations. Vulnerability severity is scored independently "
        "using official FIRST CVSS v3.0 equations (AV, AC, PR, UI, S, C, I, A). "
        "Checks representing defense-in-depth hygiene without confirmed exploit paths are marked 'Not Scored' "
        "to prevent inflated or speculative vulnerability severity."
    )

    return ScoreReport(
        final_score=normalized_score,
        letter_grade=letter_grade,
        total_possible_points=total_assessed_possible,
        earned_points=total_earned,
        breakdown=breakdown,
        critical_high_count=critical_high_count,
        summary_statement=summary,
        methodology_notes=methodology,
        max_cvss_score=max_cvss_score,
        cvss_severity_distribution=cvss_distribution,
        scored_vulnerabilities_count=scored_count,
        unscored_findings_count=unscored_count,
    )
