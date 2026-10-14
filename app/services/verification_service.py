"""Empirical Before-and-After Verification Service for GOVNEXIS 3.0."""

from typing import Dict, Any, List, Optional
from app.database.db import get_scan, get_all_scans


class VerificationService:
    """Service layer comparing empirical baseline and follow-up audit scans."""

    @staticmethod
    def get_comparison_options(limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve historical scans available for verification comparison."""
        return get_all_scans(limit=limit)

    @staticmethod
    def compare_scans(baseline_id: int, rescan_id: int) -> Optional[Dict[str, Any]]:
        """Compute comprehensive empirical delta between baseline and follow-up scans."""
        scan_a = get_scan(baseline_id)
        scan_b = get_scan(rescan_id)

        if not scan_a or not scan_b:
            return None

        # Configuration Scores and Grades
        score_a = scan_a["score"]
        score_b = scan_b["score"]
        score_delta = score_b - score_a

        grade_a = scan_a["letter_grade"]
        grade_b = scan_b["letter_grade"]

        # CVSS v3.0 Base Scores
        cvss_a = float(scan_a.get("max_cvss", 0.0) or 0.0)
        cvss_b = float(scan_b.get("max_cvss", 0.0) or 0.0)
        cvss_delta = round(cvss_b - cvss_a, 1)

        sev_a = scan_a.get("cvss_severity", "None")
        sev_b = scan_b.get("cvss_severity", "None")

        # Map findings by check_id
        findings_a = {f["check_id"]: f for f in scan_a.get("findings", [])}
        findings_b = {f["check_id"]: f for f in scan_b.get("findings", [])}

        all_checks = set(findings_a.keys()).union(set(findings_b.keys()))

        resolved = []
        remaining = []
        regressed = []
        unchanged_pass = []

        for cid in sorted(all_checks):
            fa = findings_a.get(cid)
            fb = findings_b.get(cid)

            status_a = fa["status"] if fa else "NOT ASSESSED"
            status_b = fb["status"] if fb else "NOT ASSESSED"

            item = {
                "check_id": cid,
                "title": (fb or fa)["title"],
                "category": (fb or fa)["category"],
                "status_before": status_a,
                "status_after": status_b,
                "evidence_before": fa["evidence"] if fa else "N/A",
                "evidence_after": fb["evidence"] if fb else "N/A",
                "cvss_before": fa.get("cvss_score") if fa else None,
                "cvss_after": fb.get("cvss_score") if fb else None,
            }

            was_gap = status_a in ("FAIL", "WARNING")
            is_gap = status_b in ("FAIL", "WARNING")

            if was_gap and status_b == "PASS":
                resolved.append(item)
            elif was_gap and is_gap:
                remaining.append(item)
            elif not was_gap and is_gap:
                regressed.append(item)
            elif status_a == "PASS" and status_b == "PASS":
                unchanged_pass.append(item)

        # Header Diffs
        headers_a = scan_a.get("details", {}).get("response_headers", {})
        headers_b = scan_b.get("details", {}).get("response_headers", {})

        all_header_keys = sorted(set(headers_a.keys()).union(set(headers_b.keys())), key=lambda k: k.lower())
        header_diffs = []
        for h in all_header_keys:
            val_a = headers_a.get(h)
            val_b = headers_b.get(h)
            header_diffs.append({
                "header": h,
                "before": val_a,
                "after": val_b,
                "status": "added" if val_a is None else ("removed" if val_b is None else ("changed" if val_a != val_b else "same"))
            })

        return {
            "baseline": scan_a,
            "rescan": scan_b,
            "score_a": score_a,
            "score_b": score_b,
            "score_delta": score_delta,
            "grade_a": grade_a,
            "grade_b": grade_b,
            "cvss_a": cvss_a,
            "cvss_b": cvss_b,
            "cvss_delta": cvss_delta,
            "sev_a": sev_a,
            "sev_b": sev_b,
            "resolved": resolved,
            "remaining": remaining,
            "regressed": regressed,
            "unchanged_pass": unchanged_pass,
            "header_diffs": header_diffs,
            "resolved_count": len(resolved),
            "remaining_count": len(remaining),
            "regressed_count": len(regressed),
        }
