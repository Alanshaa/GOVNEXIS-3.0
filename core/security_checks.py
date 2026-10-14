"""Security Configuration Auditing Engine for GOVNEXIS.

Implements transparent, rule-based auditing for:
- HTTPS Transport Enforcement & HTTP-to-HTTPS Redirection
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- Clickjacking Protection (X-Frame-Options / frame-ancestors)
- MIME-Sniffing Defense (X-Content-Type-Options)
- Cookie Security Flags (Secure, HttpOnly, SameSite)
- Referrer-Policy Header
- Permissions-Policy Header
- Server & Framework Banner Information Disclosures
- TLS Protocol & Certificate Hygiene Observations
"""

import re
from typing import Dict, List, Any, Optional
from core.config import (
    STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_NOT_ASSESSED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)


from core.cvss import CVSSScore, assign_finding_cvss


class FindingRecord:
    """Represents a structured security configuration check result with CVSS v3.0 scoring."""

    def __init__(
        self,
        check_id: str,
        title: str,
        category: str,
        status: str,
        severity: str,
        evidence: str,
        why_it_matters: str,
        potential_impact: str,
        recommended_action: str,
        confidence: str = "High",
        references: Optional[List[Dict[str, str]]] = None,
        cvss: Optional[CVSSScore] = None,
    ):
        self.check_id = check_id
        self.title = title
        self.category = category
        self.status = status
        self.severity = severity
        self.evidence = evidence
        self.why_it_matters = why_it_matters
        self.potential_impact = potential_impact
        self.recommended_action = recommended_action
        self.confidence = confidence
        self.references = references or []
        self.cvss = cvss or assign_finding_cvss(self.check_id, self.status, self.evidence, self.severity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "evidence": self.evidence,
            "why_it_matters": self.why_it_matters,
            "potential_impact": self.potential_impact,
            "recommended_action": self.recommended_action,
            "confidence": self.confidence,
            "references": self.references,
            "cvss": self.cvss.to_dict() if self.cvss else None,
        }


def audit_https_enforcement(
    final_url: str,
    initial_url: str,
    http_redirects: bool,
    status_code: int
) -> FindingRecord:
    """Check whether HTTPS is strictly enforced and HTTP requests cleanly redirect."""
    is_https = final_url.lower().startswith("https://")

    if is_https:
        evidence = f"Destination enforces HTTPS (Status code: {status_code}). Initial: {initial_url} -> Final: {final_url}"
        if http_redirects:
            evidence += " | Valid HTTP-to-HTTPS upgrade redirection observed."
        return FindingRecord(
            check_id="https_enforced",
            title="HTTPS Transport Enforcement",
            category="Transport Layer Security",
            status=STATUS_PASS,
            severity=SEV_INFO,
            evidence=evidence,
            why_it_matters="HTTPS encrypts all client-server communication, preventing interception and in-flight manipulation.",
            potential_impact="None identified. Web traffic is protected by TLS encryption.",
            recommended_action="Maintain automatic HTTP-to-HTTPS 301/308 redirection and TLS 1.3 enablement.",
            references=[
                {"title": "CISA BOD 18-01: Enhance Email and Web Security", "url": "https://www.cisa.gov/news-events/directives/bod-18-01"},
                {"title": "NIST SP 800-52 Rev 2: Guidelines for TLS Implementations", "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}
            ]
        )
    else:
        return FindingRecord(
            check_id="https_enforced",
            title="HTTPS Transport Enforcement",
            category="Transport Layer Security",
            status=STATUS_FAIL,
            severity=SEV_CRITICAL,
            evidence=f"Final destination uses unencrypted plaintext HTTP: {final_url} (Status: {status_code})",
            why_it_matters="Unencrypted HTTP exposes citizens and administrators to eavesdropping, credential theft, and adversary injection of rogue scripts.",
            potential_impact="Complete compromise of traffic confidentiality and data integrity on public Wi-Fi or transit networks.",
            recommended_action="Deploy a valid TLS certificate and configure web servers to redirect all HTTP traffic to HTTPS via status code 301 or 308.",
            references=[
                {"title": "CISA BOD 18-01", "url": "https://www.cisa.gov/news-events/directives/bod-18-01"},
                {"title": "The HTTPS-Only Standard (OMB M-15-13)", "url": "https://https.cio.gov/"}
            ]
        )


def audit_hsts(headers: Dict[str, str], is_https: bool) -> FindingRecord:
    """Audit HTTP Strict Transport Security (HSTS) header."""
    if not is_https:
        return FindingRecord(
            check_id="hsts_header",
            title="HTTP Strict Transport Security (HSTS)",
            category="Transport Layer Security",
            status=STATUS_NOT_ASSESSED,
            severity=SEV_HIGH,
            evidence="Target does not serve HTTPS; HSTS cannot be evaluated.",
            why_it_matters="HSTS instructs browsers to strictly communicate over HTTPS, preventing SSL stripping.",
            potential_impact="Browsers may accept unencrypted connections, leaving users vulnerable to man-in-the-middle attacks.",
            recommended_action="Enable HTTPS first, then deploy the Strict-Transport-Security header.",
            references=[{"title": "RFC 6797: HTTP Strict Transport Security", "url": "https://datatracker.ietf.org/doc/html/rfc6797"}]
        )

    hsts_val = headers.get("strict-transport-security")
    if not hsts_val:
        return FindingRecord(
            check_id="hsts_header",
            title="HTTP Strict Transport Security (HSTS)",
            category="Transport Layer Security",
            status=STATUS_FAIL,
            severity=SEV_HIGH,
            evidence="Header 'Strict-Transport-Security' is absent from HTTP response.",
            why_it_matters="Without HSTS, the initial connection can be intercepted via SSL Stripping (Downgrade Attacks) before redirecting to HTTPS.",
            potential_impact="Adversaries on local networks can intercept initial visits and redirect users to imposter portals.",
            recommended_action="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            references=[
                {"title": "RFC 6797", "url": "https://datatracker.ietf.org/doc/html/rfc6797"},
                {"title": "CISA BOD 18-01 HSTS Guidance", "url": "https://www.cisa.gov/news-events/directives/bod-18-01"}
            ]
        )

    # Parse directives
    max_age_match = re.search(r"max-age=(\d+)", hsts_val, re.IGNORECASE)
    has_subdomains = "includesubdomains" in hsts_val.lower()
    has_preload = "preload" in hsts_val.lower()

    if max_age_match:
        max_age = int(max_age_match.group(1))
        # 1 year = 31536000 seconds
        if max_age >= 31536000:
            status = STATUS_PASS
            sev = SEV_INFO
            notes = f"Optimal configuration detected (max-age={max_age}s)."
            if not has_subdomains:
                notes += " (Recommendation: include 'includeSubDomains' to protect subdomains)."
        elif max_age >= 10886400: # ~18 weeks
            status = STATUS_WARNING
            sev = SEV_MEDIUM
            notes = f"HSTS max-age is set to {max_age}s, which is below the recommended 1-year threshold (31,536,000s)."
        else:
            status = STATUS_FAIL
            sev = SEV_HIGH
            notes = f"HSTS max-age is too short ({max_age}s). Industry standard mandates at least 31,536,000 seconds."
    else:
        status = STATUS_FAIL
        sev = SEV_HIGH
        notes = "Header present but missing mandatory 'max-age' directive."

    return FindingRecord(
        check_id="hsts_header",
        title="HTTP Strict Transport Security (HSTS)",
        category="Transport Layer Security",
        status=status,
        severity=sev,
        evidence=f"Strict-Transport-Security: {hsts_val} | {notes}",
        why_it_matters="HSTS informs compliant user agents that the domain must only ever be accessed using TLS encryption.",
        potential_impact="Suboptimal HSTS duration reduces protection against SSL stripping attacks over time.",
        recommended_action="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
        references=[
            {"title": "RFC 6797", "url": "https://datatracker.ietf.org/doc/html/rfc6797"},
            {"title": "OWASP HSTS Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"}
        ]
    )


def audit_content_security_policy(headers: Dict[str, str]) -> FindingRecord:
    """Audit Content-Security-Policy (CSP) header."""
    csp_val = headers.get("content-security-policy")
    if not csp_val:
        return FindingRecord(
            check_id="content_security_policy",
            title="Content-Security-Policy (CSP)",
            category="Injection Defense",
            status=STATUS_FAIL,
            severity=SEV_HIGH,
            evidence="Header 'Content-Security-Policy' is absent from HTTP response.",
            why_it_matters="CSP provides a critical defense-in-depth layer against Cross-Site Scripting (XSS), data exfiltration, and malicious resource injection.",
            potential_impact="If an injection vulnerability exists in application code, browsers will execute untrusted adversary scripts.",
            recommended_action="Define a restrictive CSP starting with default-src 'self', specifying permitted script, style, and connect origins, or using cryptographic nonces.",
            references=[
                {"title": "W3C CSP Level 3", "url": "https://www.w3.org/TR/CSP3/"},
                {"title": "OWASP Content Security Policy Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"}
            ]
        )

    # Analyze CSP contents
    has_unsafe_inline = "'unsafe-inline'" in csp_val.lower()
    has_unsafe_eval = "'unsafe-eval'" in csp_val.lower()
    has_default_src = "default-src" in csp_val.lower()
    has_script_src = "script-src" in csp_val.lower()
    has_object_src = "object-src" in csp_val.lower()

    concerns = []
    if has_unsafe_inline:
        concerns.append("Contains 'unsafe-inline' which reduces protection against XSS")
    if has_unsafe_eval:
        concerns.append("Contains 'unsafe-eval' which permits execution of dynamic strings as code")
    if not has_default_src:
        concerns.append("Missing fallback directive 'default-src'")

    if concerns:
        return FindingRecord(
            check_id="content_security_policy",
            title="Content-Security-Policy (CSP)",
            category="Injection Defense",
            status=STATUS_WARNING,
            severity=SEV_MEDIUM,
            evidence=f"Content-Security-Policy: {csp_val} | Findings: {'; '.join(concerns)}",
            why_it_matters="CSP was detected, but permissive keywords significantly weaken the browser's ability to block injected scripts.",
            potential_impact="Injected scripts may still execute if an XSS vulnerability exists on the page.",
            recommended_action="Refactor inline event handlers and scripts to external files with nonces (e.g. 'nonce-random123') and eliminate 'unsafe-inline'.",
            references=[
                {"title": "W3C CSP Level 3", "url": "https://www.w3.org/TR/CSP3/"},
                {"title": "Google CSP Evaluator Guide", "url": "https://csp-evaluator.withgoogle.com/"}
            ]
        )

    return FindingRecord(
        check_id="content_security_policy",
        title="Content-Security-Policy (CSP)",
        category="Injection Defense",
        status=STATUS_PASS,
        severity=SEV_INFO,
        evidence=f"Content-Security-Policy: {csp_val} | Robust restrictive policy enforced.",
        why_it_matters="Strong CSP effectively limits the blast radius of injection flaws.",
        potential_impact="None. Browser enforces origin and source restrictions on loaded assets.",
        recommended_action="Maintain policy hygiene as new frontend libraries and external APIs are adopted.",
        references=[{"title": "OWASP CSP Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"}]
    )


def audit_x_frame_options(headers: Dict[str, str]) -> FindingRecord:
    """Audit Clickjacking Defense via X-Frame-Options or CSP frame-ancestors."""
    xfo_val = headers.get("x-frame-options")
    csp_val = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp_val.lower()

    if has_frame_ancestors or (xfo_val and xfo_val.upper() in ("DENY", "SAMEORIGIN")):
        evidence = []
        if xfo_val:
            evidence.append(f"X-Frame-Options: {xfo_val}")
        if has_frame_ancestors:
            # Extract frame-ancestors directive
            match = re.search(r"frame-ancestors\s+([^;]+)", csp_val, re.IGNORECASE)
            ancestors = match.group(0) if match else "frame-ancestors specified"
            evidence.append(f"CSP: {ancestors}")

        return FindingRecord(
            check_id="x_frame_options",
            title="Clickjacking Defense (X-Frame-Options / frame-ancestors)",
            category="UI Redressing",
            status=STATUS_PASS,
            severity=SEV_INFO,
            evidence="; ".join(evidence),
            why_it_matters="Prevents hostile third-party domains from embedding the government portal inside transparent iframes to trick users into unauthorized actions.",
            potential_impact="None. Web page cannot be framed by unauthorized origins.",
            recommended_action="Retain 'X-Frame-Options: DENY' (or 'SAMEORIGIN') alongside CSP 'frame-ancestors 'self''.",
            references=[
                {"title": "OWASP Clickjacking Defense", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"},
                {"title": "RFC 7034: HTTP Header Field X-Frame-Options", "url": "https://datatracker.ietf.org/doc/html/rfc7034"}
            ]
        )

    return FindingRecord(
        check_id="x_frame_options",
        title="Clickjacking Defense (X-Frame-Options / frame-ancestors)",
        category="UI Redressing",
        status=STATUS_FAIL,
        severity=SEV_MEDIUM,
        evidence="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was detected.",
        why_it_matters="Without frame restrictions, the site can be rendered inside invisible iframes on malicious sites, enabling Clickjacking attacks.",
        potential_impact="Attackers can trick authenticated government personnel or citizens into submitting unintended transactions.",
        recommended_action="Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and add 'frame-ancestors 'self'' to Content-Security-Policy.",
        references=[
            {"title": "OWASP Clickjacking Defense", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"}
        ]
    )


def audit_x_content_type_options(headers: Dict[str, str]) -> FindingRecord:
    """Audit X-Content-Type-Options header."""
    xcto_val = headers.get("x-content-type-options")
    if xcto_val and xcto_val.strip().lower() == "nosniff":
        return FindingRecord(
            check_id="x_content_type_options",
            title="MIME-Sniffing Defense (X-Content-Type-Options)",
            category="Content Handling",
            status=STATUS_PASS,
            severity=SEV_INFO,
            evidence=f"X-Content-Type-Options: {xcto_val}",
            why_it_matters="Instructs browsers to strictly honor declared MIME types and never attempt to 'sniff' or reinterpret files as executable scripts.",
            potential_impact="None. Browser honors the Content-Type header without speculative execution.",
            recommended_action="Retain 'X-Content-Type-Options: nosniff' on all server responses.",
            references=[{"title": "MDN: X-Content-Type-Options", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"}]
        )

    return FindingRecord(
        check_id="x_content_type_options",
        title="MIME-Sniffing Defense (X-Content-Type-Options)",
        category="Content Handling",
        status=STATUS_FAIL,
        severity=SEV_MEDIUM,
        evidence=f"X-Content-Type-Options is {'missing' if not xcto_val else f'improperly configured: {xcto_val}'}.",
        why_it_matters="In the absence of 'nosniff', browsers may inspect non-executable files (e.g., uploaded avatars, text logs) and execute them if they contain script tags.",
        potential_impact="MIME confusion attacks leading to stored Cross-Site Scripting (XSS) via user uploads.",
        recommended_action="Add 'X-Content-Type-Options: nosniff' across all web server responses.",
        references=[{"title": "Fetch Standard: MIME Type Sniffing", "url": "https://mimesniff.spec.whatwg.org/"}]
    )


def audit_cookies(cookie_headers: List[str], is_https: bool) -> FindingRecord:
    """Audit Set-Cookie attributes for Secure, HttpOnly, and SameSite."""
    if not cookie_headers:
        return FindingRecord(
            check_id="secure_cookies",
            title="Cookie Security Attributes (Secure, HttpOnly, SameSite)",
            category="Session Integrity",
            status=STATUS_PASS,
            severity=SEV_INFO,
            evidence="No Set-Cookie headers were returned in this response (Stateless / Cookie-free response).",
            why_it_matters="Cookies that manage session state or authentication require defense-in-depth protection flags.",
            potential_impact="None observed. Target did not set cookies on initial landing response.",
            recommended_action="When cookies are introduced, always affix Secure, HttpOnly, and SameSite=Lax/Strict flags.",
            references=[{"title": "RFC 6265bis: Cookies", "url": "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"}]
        )

    cookie_issues = []
    total_cookies = len(cookie_headers)

    for idx, raw_cookie in enumerate(cookie_headers, start=1):
        cookie_parts = [p.strip() for p in raw_cookie.split(";")]
        cookie_name = cookie_parts[0].split("=")[0] if cookie_parts else f"Cookie#{idx}"
        flags_lower = [p.lower() for p in cookie_parts]

        has_secure = "secure" in flags_lower
        has_httponly = "httponly" in flags_lower
        samesite_flag = next((p for p in flags_lower if p.startswith("samesite")), None)

        missing_flags = []
        if not has_secure and is_https:
            missing_flags.append("Secure flag missing (risk of plaintext transmission)")
        if not has_httponly:
            missing_flags.append("HttpOnly flag missing (accessible to JavaScript DOM / XSS)")
        if not samesite_flag:
            missing_flags.append("SameSite flag missing (risk of CSRF)")

        if missing_flags:
            cookie_issues.append(f"'{cookie_name}': {', '.join(missing_flags)}")

    if cookie_issues:
        evidence_str = f"Found {total_cookies} cookie(s). Issues: " + " | ".join(cookie_issues)
        return FindingRecord(
            check_id="secure_cookies",
            title="Cookie Security Attributes (Secure, HttpOnly, SameSite)",
            category="Session Integrity",
            status=STATUS_FAIL,
            severity=SEV_MEDIUM,
            evidence=evidence_str,
            why_it_matters="Without Secure, HttpOnly, and SameSite flags, session identifiers are vulnerable to network interception, DOM-based theft via XSS, and Cross-Site Request Forgery (CSRF).",
            potential_impact="Session hijacking, token exfiltration, and unauthorized state changes on behalf of authenticated users.",
            recommended_action="Append '; Secure; HttpOnly; SameSite=Lax' (or SameSite=Strict) to all Set-Cookie directives.",
            references=[
                {"title": "OWASP Session Management Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
                {"title": "MDN: Set-Cookie Attributes", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"}
            ]
        )

    return FindingRecord(
        check_id="secure_cookies",
        title="Cookie Security Attributes (Secure, HttpOnly, SameSite)",
        category="Session Integrity",
        status=STATUS_PASS,
        severity=SEV_INFO,
        evidence=f"Audited {total_cookies} cookie(s): All set with Secure, HttpOnly, and SameSite controls.",
        why_it_matters="Proper flags safeguard session tokens against script access, cleartext leakage, and cross-site requests.",
        potential_impact="None. Session cookies follow modern defense-in-depth best practices.",
        recommended_action="Maintain cookie hygiene across all application microservices.",
        references=[{"title": "RFC 6265bis", "url": "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis"}]
    )


def audit_referrer_policy(headers: Dict[str, str]) -> FindingRecord:
    """Audit Referrer-Policy header."""
    ref_val = headers.get("referrer-policy")
    recommended_policies = (
        "strict-origin-when-cross-origin",
        "no-referrer",
        "same-origin",
        "strict-origin"
    )

    if not ref_val:
        return FindingRecord(
            check_id="referrer_policy",
            title="Referrer-Policy Header",
            category="Information Disclosure",
            status=STATUS_WARNING,
            severity=SEV_LOW,
            evidence="Header 'Referrer-Policy' is absent from HTTP response.",
            why_it_matters="Without an explicit policy, browsers may leak full URL paths and query strings (which may contain sensitive tokens, case IDs, or national identifiers) to external links.",
            potential_impact="Accidental exposure of sensitive internal portal URLs and query parameters in third-party server logs.",
            recommended_action="Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            references=[{"title": "W3C Referrer Policy", "url": "https://www.w3.org/TR/referrer-policy/"}]
        )

    cleaned_val = ref_val.strip().lower()
    if any(p in cleaned_val for p in recommended_policies):
        return FindingRecord(
            check_id="referrer_policy",
            title="Referrer-Policy Header",
            category="Information Disclosure",
            status=STATUS_PASS,
            severity=SEV_INFO,
            evidence=f"Referrer-Policy: {ref_val}",
            why_it_matters="Controls how much referrer information (URL path, parameters) is sent when navigating to external websites.",
            potential_impact="None. Referrer leakage is appropriately restricted.",
            recommended_action="Retain strict-origin-when-cross-origin across responses.",
            references=[{"title": "W3C Referrer Policy", "url": "https://www.w3.org/TR/referrer-policy/"}]
        )
    else:
        return FindingRecord(
            check_id="referrer_policy",
            title="Referrer-Policy Header",
            category="Information Disclosure",
            status=STATUS_WARNING,
            severity=SEV_LOW,
            evidence=f"Referrer-Policy: {ref_val} (permits broad URL disclosure).",
            why_it_matters="Weak policies like 'unsafe-url' leak sensitive internal path information to third parties.",
            potential_impact="Information disclosure in third-party web logs.",
            recommended_action="Change Referrer-Policy to 'strict-origin-when-cross-origin'.",
            references=[{"title": "W3C Referrer Policy", "url": "https://www.w3.org/TR/referrer-policy/"}]
        )


def audit_permissions_policy(headers: Dict[str, str]) -> FindingRecord:
    """Audit Permissions-Policy header."""
    perm_val = headers.get("permissions-policy") or headers.get("feature-policy")

    if not perm_val:
        return FindingRecord(
            check_id="permissions_policy",
            title="Permissions-Policy Header",
            category="Feature Governance",
            status=STATUS_WARNING,
            severity=SEV_LOW,
            evidence="Header 'Permissions-Policy' is absent from HTTP response.",
            why_it_matters="Permissions-Policy allows site operators to restrict sensitive browser APIs (microphone, camera, geolocation, FIDO2) to prevent unauthorized misuse by embedded third-party widgets.",
            potential_impact="Embedded scripts or iframes could attempt to request access to device hardware and APIs.",
            recommended_action="Add 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'.",
            references=[{"title": "W3C Permissions Policy", "url": "https://www.w3.org/TR/permissions-policy-1/"}]
        )

    return FindingRecord(
        check_id="permissions_policy",
        title="Permissions-Policy Header",
        category="Feature Governance",
        status=STATUS_PASS,
        severity=SEV_INFO,
        evidence=f"Permissions-Policy: {perm_val}",
        why_it_matters="Controls access to hardware sensors and powerful browser features.",
        potential_impact="None. Hardware features are explicitly governed.",
        recommended_action="Review policy periodically as new browser capabilities are standardized.",
        references=[{"title": "W3C Permissions Policy", "url": "https://www.w3.org/TR/permissions-policy-1/"}]
    )


def audit_server_disclosure(headers: Dict[str, str]) -> FindingRecord:
    """Audit Server and X-Powered-By banners for version and OS fingerprinting."""
    server_val = headers.get("server")
    powered_by = headers.get("x-powered-by")
    aspnet_val = headers.get("x-aspnet-version")

    disclosures = []
    if server_val:
        # Check for detailed versions like Apache/2.4.41 or Ubuntu or PHP/7.4
        if re.search(r"(\d+\.\d+|\bubuntu\b|\bdebian\b|\bcentos\b|\brhel\b)", server_val, re.IGNORECASE):
            disclosures.append(f"Server header exposes software and version details: '{server_val}'")
    if powered_by:
        disclosures.append(f"X-Powered-By header discloses underlying tech stack: '{powered_by}'")
    if aspnet_val:
        disclosures.append(f"X-AspNet-Version discloses framework version: '{aspnet_val}'")

    if disclosures:
        return FindingRecord(
            check_id="server_disclosure",
            title="Server Information Disclosure",
            category="Information Disclosure",
            status=STATUS_FAIL,
            severity=SEV_LOW,
            evidence=" | ".join(disclosures),
            why_it_matters="Verbose server banners provide reconnaissance data to adversaries, allowing them to map specific CVE vulnerabilities to your software versions.",
            potential_impact="Adversaries can tailor exploits directly to known unpatched flaws in the disclosed web server or framework version.",
            recommended_action="Sanitize or suppress the Server header (e.g. ServerTokens Prod) and remove X-Powered-By headers.",
            references=[{"title": "OWASP Fingerprint Web Server", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"}]
        )

    evidence_msg = "Clean server banners. "
    if server_val:
        evidence_msg += f"Generic Server header: '{server_val}'. "
    else:
        evidence_msg += "No Server header disclosed. "
    evidence_msg += "No X-Powered-By or framework banners present."

    return FindingRecord(
        check_id="server_disclosure",
        title="Server Information Disclosure",
        category="Information Disclosure",
        status=STATUS_PASS,
        severity=SEV_INFO,
        evidence=evidence_msg,
        why_it_matters="Minimizing software banner disclosure slows adversary automated fingerprinting.",
        potential_impact="None. Minimal reconnaissance information provided.",
        recommended_action="Maintain server token obfuscation in production reverse proxies.",
        references=[{"title": "OWASP Web Security Testing Guide", "url": "https://owasp.org/www-project-web-security-testing-guide/"}]
    )


def audit_tls_configuration(tls_info: Optional[Dict[str, Any]], is_https: bool) -> FindingRecord:
    """Audit TLS protocol version and certificate expiry observations."""
    if not is_https or not tls_info:
        return FindingRecord(
            check_id="tls_configuration",
            title="TLS Protocol & Certificate Hygiene",
            category="Cryptographic Hygiene",
            status=STATUS_NOT_ASSESSED,
            severity=SEV_LOW,
            evidence="TLS observations unavailable or connection is plaintext HTTP.",
            why_it_matters="Modern TLS protocols (TLS 1.2 and 1.3) and valid digital certificates guarantee cryptographic security.",
            potential_impact="Cannot evaluate cryptographic posture without an active TLS endpoint.",
            recommended_action="Enable HTTPS and inspect TLS certificate validity.",
            references=[{"title": "NIST SP 800-52 Rev 2", "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}]
        )

    protocol_version = tls_info.get("protocol", "Unknown")
    days_left = tls_info.get("days_until_expiry")
    issuer = tls_info.get("issuer_common_name", "Unknown Issuer")
    subject = tls_info.get("subject_common_name", "Unknown Subject")
    cipher = tls_info.get("cipher", "Unknown Cipher")

    evidence_parts = [
        f"Protocol: {protocol_version}",
        f"Cipher: {cipher}",
        f"Subject: {subject}",
        f"Issuer: {issuer}"
    ]
    if days_left is not None:
        evidence_parts.append(f"Certificate validity: {days_left} days remaining")

    # Evaluate protocol version
    if protocol_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        return FindingRecord(
            check_id="tls_configuration",
            title="TLS Protocol & Certificate Hygiene",
            category="Cryptographic Hygiene",
            status=STATUS_FAIL,
            severity=SEV_HIGH,
            evidence=" | ".join(evidence_parts) + f" (Legacy protocol {protocol_version} is deprecated).",
            why_it_matters="Legacy TLS protocols (TLS 1.0, 1.1) and SSL are broken and vulnerable to attacks such as BEAST, POODLE, and Sweet32.",
            potential_impact="Interception or cryptographic decryption of encrypted government citizen traffic.",
            recommended_action="Disable TLS 1.0 and 1.1 on the server. Mandate TLS 1.2 and TLS 1.3 only.",
            references=[{"title": "NIST SP 800-52 Rev 2", "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}]
        )

    # Evaluate certificate expiration
    if days_left is not None and days_left < 0:
        return FindingRecord(
            check_id="tls_configuration",
            title="TLS Protocol & Certificate Hygiene",
            category="Cryptographic Hygiene",
            status=STATUS_FAIL,
            severity=SEV_CRITICAL,
            evidence=" | ".join(evidence_parts) + f" (CERTIFICATE EXPIRED {abs(days_left)} days ago).",
            why_it_matters="An expired digital certificate triggers prominent browser security warnings and destroys public trust.",
            potential_impact="Users are blocked from accessing the site; vulnerable to impersonation.",
            recommended_action="Renew the TLS certificate immediately using automated ACME / Let's Encrypt or your approved CA.",
            references=[{"title": "CA/Browser Forum Baseline Requirements", "url": "https://cabforum.org/"}]
        )
    elif days_left is not None and days_left < 15:
        return FindingRecord(
            check_id="tls_configuration",
            title="TLS Protocol & Certificate Hygiene",
            category="Cryptographic Hygiene",
            status=STATUS_WARNING,
            severity=SEV_MEDIUM,
            evidence=" | ".join(evidence_parts) + f" (Certificate expires soon: {days_left} days remaining).",
            why_it_matters="Certificates approaching expiration must be renewed before expiration to avoid service interruption.",
            potential_impact="Service disruption and browser certificate security warnings upon expiration.",
            recommended_action="Initiate automated certificate renewal.",
            references=[{"title": "NIST SP 800-52 Rev 2", "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}]
        )

    return FindingRecord(
        check_id="tls_configuration",
        title="TLS Protocol & Certificate Hygiene",
        category="Cryptographic Hygiene",
        status=STATUS_PASS,
        severity=SEV_INFO,
        evidence=" | ".join(evidence_parts),
        why_it_matters="Modern TLS version and valid digital certificate observed.",
        potential_impact="None. Strong cryptographic parameters verified.",
        recommended_action="Maintain automated certificate lifecycle renewal.",
        references=[{"title": "NIST SP 800-52 Rev 2", "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}]
    )
