"""Official Common Vulnerability Scoring System (CVSS) v3.0 Engine for GOVNEXIS.

Implements the official FIRST CVSS v3.0 specification:
- Exploitability metrics: Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI)
- Impact metrics: Scope (S), Confidentiality (C), Integrity (I), Availability (A)
- Official base score equations, Scope transition adjustments, and CVSS v3.0 Roundup rules
- Vector string parsing and serialization (e.g. CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Defensible mapping and 'Not Scored' tracking for passive configuration audit findings
"""

import math
from typing import Dict, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Official CVSS v3.0 Metric Values and Weights
# ---------------------------------------------------------------------------

AV_WEIGHTS: Dict[str, float] = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

AC_WEIGHTS: Dict[str, float] = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

# Privileges Required weights depend on Scope!
PR_WEIGHTS: Dict[str, Dict[str, float]] = {
    "U": {  # Scope Unchanged
        "N": 0.85,  # None
        "L": 0.62,  # Low
        "H": 0.27,  # High
    },
    "C": {  # Scope Changed
        "N": 0.85,  # None
        "L": 0.68,  # Low
        "H": 0.50,  # High
    },
}

UI_WEIGHTS: Dict[str, float] = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

CIA_WEIGHTS: Dict[str, float] = {
    "N": 0.0,   # None
    "L": 0.22,  # Low
    "H": 0.56,  # High
}

# Official metric name expansions for reporting
METRIC_NAMES: Dict[str, Dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}


# ---------------------------------------------------------------------------
# Official CVSS v3.0 Rounding Function
# ---------------------------------------------------------------------------

def cvss30_roundup(val: float) -> float:
    """Official CVSS v3.0 Roundup function.

    Defined by FIRST as the smallest number, specified to one decimal place,
    that is equal to or higher than its input (e.g. 4.02 -> 4.1, 4.00 -> 4.0).
    A tiny epsilon is applied to prevent floating-point representation quirks
    (such as 4.000000000000001 becoming 4.1).
    """
    return math.ceil(round(val, 9) * 10.0) / 10.0


# ---------------------------------------------------------------------------
# CVSS v3.0 Base Score Calculation
# ---------------------------------------------------------------------------

def calculate_cvss30_base_score(
    av: str,
    ac: str,
    pr: str,
    ui: str,
    s: str,
    c: str,
    i: str,
    a: str,
) -> float:
    """Calculate the official CVSS v3.0 Base Score from metric codes.

    Args:
        av: Attack Vector ('N', 'A', 'L', 'P')
        ac: Attack Complexity ('L', 'H')
        pr: Privileges Required ('N', 'L', 'H')
        ui: User Interaction ('N', 'R')
        s:  Scope ('U', 'C')
        c:  Confidentiality Impact ('N', 'L', 'H')
        i:  Integrity Impact ('N', 'L', 'H')
        a:  Availability Impact ('N', 'L', 'H')

    Returns:
        CVSS v3.0 Base Score rounded to one decimal place (0.0 to 10.0).
    """
    # Validate metric codes
    if av not in AV_WEIGHTS:
        raise ValueError(f"Invalid Attack Vector: {av}")
    if ac not in AC_WEIGHTS:
        raise ValueError(f"Invalid Attack Complexity: {ac}")
    if s not in PR_WEIGHTS:
        raise ValueError(f"Invalid Scope: {s}")
    if pr not in PR_WEIGHTS[s]:
        raise ValueError(f"Invalid Privileges Required: {pr}")
    if ui not in UI_WEIGHTS:
        raise ValueError(f"Invalid User Interaction: {ui}")
    if c not in CIA_WEIGHTS or i not in CIA_WEIGHTS or a not in CIA_WEIGHTS:
        raise ValueError(f"Invalid CIA Impact metric: C={c}, I={i}, A={a}")

    # 1. Calculate Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - CIA_WEIGHTS[c]) * (1.0 - CIA_WEIGHTS[i]) * (1.0 - CIA_WEIGHTS[a]))
    if iss <= 0.0:
        return 0.0

    # 2. Calculate Impact depending on Scope
    if s == "U":
        impact = 6.42 * iss
    else:  # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # 3. Calculate Exploitability
    exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * PR_WEIGHTS[s][pr] * UI_WEIGHTS[ui]

    # 4. Calculate Base Score
    if impact <= 0.0:
        return 0.0

    if s == "U":
        base_score = cvss30_roundup(min(impact + exploitability, 10.0))
    else:
        base_score = cvss30_roundup(min(1.08 * (impact + exploitability), 10.0))

    return max(0.0, min(10.0, base_score))


SEV_NONE = "None"
SEV_LOW = "Low"
SEV_MEDIUM = "Medium"
SEV_HIGH = "High"
SEV_CRITICAL = "Critical"


def get_cvss30_severity(score: Optional[float]) -> str:
    """Return the official CVSS v3.0 qualitative severity rating.

    None:     0.0
    Low:      0.1 - 3.9
    Medium:   4.0 - 6.9
    High:     7.0 - 8.9
    Critical: 9.0 - 10.0
    """
    if score is None:
        return "Not Scored"
    if score == 0.0:
        return SEV_NONE
    elif score < 4.0:
        return SEV_LOW
    elif score < 7.0:
        return SEV_MEDIUM
    elif score < 9.0:
        return SEV_HIGH
    else:
        return SEV_CRITICAL


def build_cvss30_vector(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> str:
    """Construct a standard CVSS v3.0 vector string."""
    return f"CVSS:3.0/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def parse_cvss30_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS v3.0 vector string into a dictionary of metric codes."""
    if not vector.startswith("CVSS:3.0/"):
        raise ValueError(f"Vector string must start with 'CVSS:3.0/': {vector}")

    parts = vector[len("CVSS:3.0/"):].split("/")
    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        metrics[k.strip().upper()] = v.strip().upper()

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [m for m in required if m not in metrics]
    if missing:
        raise ValueError(f"Vector missing required base metrics: {missing}")

    return metrics


# ---------------------------------------------------------------------------
# Structured CVSS Score Container
# ---------------------------------------------------------------------------

class CVSSScore:
    """Encapsulates a finding's CVSS v3.0 score, vector, and scoring status."""

    def __init__(
        self,
        base_score: Optional[float] = None,
        severity: str = "Not Scored",
        vector_string: Optional[str] = None,
        metrics: Optional[Dict[str, str]] = None,
        status: str = "Not Scored",
        unscored_reason: Optional[str] = None,
    ):
        self.base_score = base_score
        self.severity = severity
        self.vector_string = vector_string
        self.metrics = metrics or {}
        self.status = status
        self.unscored_reason = unscored_reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_score": self.base_score,
            "severity": self.severity,
            "vector_string": self.vector_string,
            "metrics": self.metrics,
            "status": self.status,
            "unscored_reason": self.unscored_reason,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "CVSSScore":
        if not data:
            return cls()
        return cls(
            base_score=data.get("base_score"),
            severity=data.get("severity", "Not Scored"),
            vector_string=data.get("vector_string"),
            metrics=data.get("metrics") or {},
            status=data.get("status", "Not Scored"),
            unscored_reason=data.get("unscored_reason"),
        )

    @classmethod
    def create_scored(
        cls,
        av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
    ) -> "CVSSScore":
        """Compute score from metrics and build a scored CVSSScore instance."""
        score = calculate_cvss30_base_score(av, ac, pr, ui, s, c, i, a)
        sev = get_cvss30_severity(score)
        vector = build_cvss30_vector(av, ac, pr, ui, s, c, i, a)
        metrics = {
            "AV": av, "AC": ac, "PR": pr, "UI": ui,
            "S": s, "C": c, "I": i, "A": a,
        }
        return cls(
            base_score=score,
            severity=sev,
            vector_string=vector,
            metrics=metrics,
            status="SCORED",
            unscored_reason=None,
        )

    @classmethod
    def create_unscored(cls, reason: str) -> "CVSSScore":
        """Build an unscored CVSSScore instance with explanation."""
        return cls(
            base_score=None,
            severity="Not Scored",
            vector_string=None,
            metrics={},
            status="NOT_SCORED",
            unscored_reason=reason,
        )

    @classmethod
    def create_passed(cls) -> "CVSSScore":
        """Build a None (0.0) score for a clean check passing audit."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        metrics = {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "N", "I": "N", "A": "N"
        }
        return cls(
            base_score=0.0,
            severity=SEV_NONE,
            vector_string=vector,
            metrics=metrics,
            status="SCORED",
            unscored_reason=None,
        )


# ---------------------------------------------------------------------------
# Defensible CVSS v3.0 Mapping for GOVNEXIS Configuration Checks
# ---------------------------------------------------------------------------

def assign_finding_cvss(
    check_id: str,
    status: str,
    evidence: str = "",
    severity_label: str = "",
) -> CVSSScore:
    """Map a GOVNEXIS security finding to an authentic CVSS v3.0 score.

    Rules:
    - PASS findings represent absence of a vulnerability: CVSS 0.0 (None).
    - NOT ASSESSED findings cannot be scored: Not Scored.
    - Missing defense-in-depth headers that do not establish an exploitable flaw
      are marked 'Not Scored' with a detailed explanation of missing information.
    - Configuration flaws with direct network exploit paths (e.g. plaintext HTTP,
      expired certificates, legacy SSL/TLS, clickjacking via framing) are scored
      using defensible CVSS v3.0 base metrics.
    """
    st_upper = (status or "").upper().strip()
    if st_upper == "PASS":
        return CVSSScore.create_passed()

    if st_upper in ("NOT ASSESSED", "NOT_ASSESSED"):
        return CVSSScore.create_unscored(
            "Check was not assessed during this audit pass; insufficient data to calculate CVSS."
        )

    cid = (check_id or "").lower().strip()

    # 1. HTTPS Transport Enforcement
    if cid in ("https_enforced", "https"):
        if st_upper == "FAIL":
            # Target does not support HTTPS; all citizen traffic is plaintext
            # AV:N / AC:H (MitM position required) / PR:N / UI:N / S:U / C:H / I:H / A:N -> 7.4 High
            return CVSSScore.create_scored("N", "H", "N", "N", "U", "H", "H", "N")
        else:
            # WARNING: Destination supports HTTPS but initial HTTP does not redirect
            # AV:N / AC:H / PR:N / UI:R (user must initiate plaintext request) / S:U / C:H / I:H / A:N -> 6.8 Medium
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "H", "H", "N")

    # 2. HTTP Strict Transport Security (HSTS)
    elif cid in ("hsts_header", "hsts"):
        if st_upper == "FAIL":
            # HSTS missing entirely; vulnerable to SSL stripping on initial connection
            # AV:N / AC:H (MitM required) / PR:N / UI:R / S:U / C:H / I:H / A:N -> 6.8 Medium
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "H", "H", "N")
        else:
            # WARNING: Low max-age (< 1 year) or missing includeSubDomains
            # AV:N / AC:H / PR:N / UI:R / S:U / C:L / I:L / A:N -> 4.2 Medium
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "L", "L", "N")

    # 3. Content-Security-Policy (CSP)
    elif cid in ("content_security_policy", "csp"):
        # Missing or weak CSP is a mitigating control, not proof of an existing XSS flaw.
        return CVSSScore.create_unscored(
            "Absence of Content-Security-Policy is a defense-in-depth hygiene gap. "
            "A reliable CVSS score requires an identified, exploitable injection flaw "
            "(e.g., CWE-79 XSS) on the target, which passive header inspection cannot confirm."
        )

    # 4. Clickjacking Defense (X-Frame-Options / frame-ancestors)
    elif cid in ("x_frame_options", "clickjacking_defense", "clickjacking"):
        # Direct framing vulnerability (CWE-1021)
        # AV:N / AC:L / PR:N / UI:R (user clicks framed page) / S:U / C:N / I:L (unintended click/action) / A:N -> 4.3 Medium
        return CVSSScore.create_scored("N", "L", "N", "R", "U", "N", "L", "N")

    # 5. MIME-Sniffing Defense (X-Content-Type-Options)
    elif cid in ("x_content_type_options", "mime_sniffing"):
        return CVSSScore.create_unscored(
            "Missing 'X-Content-Type-Options: nosniff' leaves browsers vulnerable to MIME confusion "
            "only if user-supplied content or unvalidated uploads are served. "
            "Without confirmed upload endpoints, an exploit vector cannot be established."
        )

    # 6. Cookie Security Attributes (Secure, HttpOnly, SameSite)
    elif cid in ("secure_cookies", "cookie_security", "cookies"):
        evidence_lower = evidence.lower()
        if "missing 'secure'" in evidence_lower or "secure" in evidence_lower:
            # Sensitive cookie sent over unencrypted transport (CWE-614)
            # AV:N / AC:H (network sniffing required) / PR:N / UI:R / S:U / C:H / I:N / A:N -> 5.3 Medium
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "H", "N", "N")
        elif "missing 'httponly'" in evidence_lower or "httponly" in evidence_lower:
            # Cookie accessible via document.cookie; increases XSS blast radius
            # AV:N / AC:H / PR:N / UI:R / S:U / C:L / I:N / A:N -> 3.1 Low
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "L", "N", "N")
        else:
            # SameSite missing; contextual CSRF defense
            # AV:N / AC:H / PR:N / UI:R / S:U / C:N / I:L / A:N -> 3.1 Low
            return CVSSScore.create_scored("N", "H", "N", "R", "U", "N", "L", "N")

    # 7. Referrer-Policy
    elif cid == "referrer_policy":
        return CVSSScore.create_unscored(
            "Permissive or absent Referrer-Policy represents a data privacy configuration gap. "
            "Without evidence that sensitive session tokens or PII are embedded in URL query strings, "
            "exploitability and confidentiality impact cannot be determined."
        )

    # 8. Permissions-Policy
    elif cid == "permissions_policy":
        return CVSSScore.create_unscored(
            "Permissions-Policy is an optional browser feature governance mechanism. "
            "Absent headers do not represent an exploitable flaw unless an active vulnerability "
            "abuses client hardware APIs (camera, microphone, geolocation)."
        )

    # 9. Server Information Disclosure
    elif cid == "server_disclosure":
        evidence_lower = evidence.lower()
        if "/" in evidence or any(c in evidence_lower for c in ("apache", "nginx", "iis", "openssl", "php", "ubuntu")):
            # Leaking detailed server and OS version (e.g. Apache/2.4.41 Ubuntu) -> Reconnaissance (CWE-200)
            # AV:N / AC:L / PR:N / UI:N / S:U / C:L (low info disclosure) / I:N / A:N -> 5.3 Medium
            return CVSSScore.create_scored("N", "L", "N", "N", "U", "L", "N", "N")
        elif st_upper == "FAIL":
            return CVSSScore.create_scored("N", "L", "N", "N", "U", "L", "N", "N")
        else:
            # Generic banner (e.g. Server: nginx) without patch/version
            return CVSSScore.create_unscored(
                "Generic web server banner (without specific patch or build version) provides "
                "minimal reconnaissance value and does not constitute an actionable vulnerability."
            )

    # 10. TLS Protocol & Certificate Hygiene
    elif cid in ("tls_configuration", "tls"):
        evidence_lower = evidence.lower()
        if "expired" in evidence_lower:
            # Certificate expired -> Complete denial of secure service / warning bypass
            # AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H -> 7.5 High
            return CVSSScore.create_scored("N", "L", "N", "N", "U", "N", "N", "H")
        elif any(proto in evidence_lower for proto in ("tlsv1.0", "tlsv1.1", "sslv2", "sslv3")):
            # Broken cryptographic protocol (POODLE, BEAST, SWEET32)
            # AV:N / AC:H (cryptanalytic/MitM attack) / PR:N / UI:N / S:U / C:H / I:H / A:N -> 7.4 High
            return CVSSScore.create_scored("N", "H", "N", "N", "U", "H", "H", "N")
        else:
            # General TLS issue
            return CVSSScore.create_scored("N", "L", "N", "N", "U", "N", "N", "H")

    return CVSSScore.create_unscored(
        "Insufficient passive technical evidence to establish an exploit vector."
    )
