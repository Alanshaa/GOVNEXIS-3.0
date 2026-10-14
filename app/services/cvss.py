"""Official FIRST CVSS v3.0 Engine for GOVNEXIS 3.0."""

from core.cvss import (
    CVSSScore,
    cvss30_roundup,
    calculate_cvss30_base_score,
    build_cvss30_vector,
    parse_cvss30_vector,
    assign_finding_cvss,
    AV_WEIGHTS,
    AC_WEIGHTS,
    PR_WEIGHTS,
    UI_WEIGHTS,
    CIA_WEIGHTS,
    METRIC_NAMES,
)

__all__ = [
    "CVSSScore",
    "cvss30_roundup",
    "calculate_cvss30_base_score",
    "build_cvss30_vector",
    "parse_cvss30_vector",
    "assign_finding_cvss",
    "AV_WEIGHTS",
    "AC_WEIGHTS",
    "PR_WEIGHTS",
    "UI_WEIGHTS",
    "CIA_WEIGHTS",
    "METRIC_NAMES",
]
