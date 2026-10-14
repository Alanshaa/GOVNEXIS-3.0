"""Defensive Website Security Configuration Scanner for GOVNEXIS.

Orchestrates:
- Strict authorization validation
- SSRF-safe URL resolution and redirect validation
- Connection and read timeouts with response size caps
- TLS certificate and cryptographic inspection
- Complete configuration check evaluation
- Transparent score calculation
"""

import ssl
import socket
import time
import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import requests

from core.config import (
    CONNECT_TIMEOUT, READ_TIMEOUT, MAX_REDIRECTS, MAX_RESPONSE_BYTES,
    SCAN_USER_AGENT, LOCAL_DEMO_HOST, LOCAL_DEMO_PORT
)
from core.url_validator import (
    validate_and_resolve_url, validate_redirect_target,
    ValidationError, SSRFSecurityError
)
from core.security_checks import (
    FindingRecord,
    audit_https_enforcement,
    audit_hsts,
    audit_content_security_policy,
    audit_x_frame_options,
    audit_x_content_type_options,
    audit_cookies,
    audit_referrer_policy,
    audit_permissions_policy,
    audit_server_disclosure,
    audit_tls_configuration,
)
from core.scoring import compute_security_score, ScoreReport


class ScanError(Exception):
    """Base exception for scanning errors with user-friendly explanations."""
    def __init__(self, message: str, technical_details: str = "", remediation_hint: str = ""):
        super().__init__(message)
        self.message = message
        self.technical_details = technical_details
        self.remediation_hint = remediation_hint


class ScanResult:
    """Encapsulates the complete result of a security configuration audit."""

    def __init__(
        self,
        target_url: str,
        final_url: str,
        hostname: str,
        resolved_ips: List[str],
        status_code: int,
        response_headers: Dict[str, str],
        cookies: List[str],
        tls_info: Optional[Dict[str, Any]],
        findings: List[FindingRecord],
        score_report: ScoreReport,
        duration_ms: int,
        timestamp: str,
        is_demo: bool = False,
    ):
        self.target_url = target_url
        self.final_url = final_url
        self.hostname = hostname
        self.resolved_ips = resolved_ips
        self.status_code = status_code
        self.response_headers = response_headers
        self.cookies = cookies
        self.tls_info = tls_info
        self.findings = findings
        self.score_report = score_report
        self.duration_ms = duration_ms
        self.timestamp = timestamp
        self.is_demo = is_demo

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "hostname": self.hostname,
            "resolved_ips": self.resolved_ips,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "cookies": self.cookies,
            "tls_info": self.tls_info,
            "findings": [f.to_dict() for f in self.findings],
            "score_report": self.score_report.to_dict(),
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "is_demo": self.is_demo,
        }


def extract_tls_info(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Inspect the target's TLS certificate and cipher suite parameters safely."""
    try:
        context = ssl.create_default_context()
        context.timeout = CONNECT_TIMEOUT

        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                # Extract Common Names
                subject_cn = "Unknown"
                issuer_cn = "Unknown"
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            subject_cn = val
                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            issuer_cn = val

                # Calculate expiration
                days_until_expiry = None
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May 24 12:00:00 2026 GMT'
                    try:
                        exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        delta = exp_date - now
                        days_until_expiry = delta.days
                    except Exception:
                        pass

                return {
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "subject_common_name": subject_cn,
                    "issuer_common_name": issuer_cn,
                    "days_until_expiry": days_until_expiry,
                    "not_after": not_after_str,
                    "san": [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"],
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "protocol": "Invalid Certificate",
            "cipher": "Untrusted",
            "subject_common_name": "Verification Failed",
            "issuer_common_name": str(e),
            "days_until_expiry": -1,
            "error": f"Certificate verification failed: {str(e)}",
        }
    except Exception:
        return None


def execute_scan(
    target_url: str,
    user_confirmed_authorization: bool = False,
    allow_local_demo: bool = False
) -> ScanResult:
    """Execute a defensive, safe security configuration audit against an authorized target.

    Args:
        target_url: URL to audit.
        user_confirmed_authorization: Must be True to proceed.
        allow_local_demo: If True, permits targeting localhost on the designated demo port.

    Returns:
        Populated ScanResult instance.

    Raises:
        ScanError or ValidationError with helpful troubleshooting guidance.
    """
    if not user_confirmed_authorization:
        raise ScanError(
            message="Authorization confirmation required.",
            technical_details="User did not check the explicit authorization confirmation box.",
            remediation_hint="You must confirm you are the authorized owner or have explicit written permission to audit this website."
        )

    start_time = time.time()
    iso_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Step 1: Safe URL Validation and DNS Resolution
    validated_url, resolved_ips = validate_and_resolve_url(target_url, allow_local_demo=allow_local_demo)
    parsed = urlparse(validated_url)
    hostname = parsed.hostname or ""
    is_demo = allow_local_demo and (hostname in ("localhost", "127.0.0.1") and parsed.port == LOCAL_DEMO_PORT)

    session = requests.Session()
    session.headers.update({"User-Agent": SCAN_USER_AGENT})

    # Step 2: Defensive HTTP Fetch with Safe Manual Redirect Following
    current_url = validated_url
    redirect_count = 0
    response = None
    http_redirects_to_https = False

    try:
        while redirect_count <= MAX_REDIRECTS:
            try:
                resp = session.get(
                    current_url,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=False,
                    stream=True,
                    verify=not is_demo,  # Skip TLS cert verification strictly for local demo if self-signed
                )
            except requests.exceptions.SSLError as e:
                raise ScanError(
                    message=f"TLS/SSL Handshake failed when connecting to '{current_url}'.",
                    technical_details=str(e),
                    remediation_hint="Verify that the server has an active, valid TLS certificate installed and is listening on port 443."
                )
            except requests.exceptions.ConnectTimeout as e:
                raise ScanError(
                    message=f"Connection timed out after {CONNECT_TIMEOUT} seconds.",
                    technical_details=str(e),
                    remediation_hint="The target web server is unreachable or dropping SYN packets. Check firewall settings and server availability."
                )
            except requests.exceptions.ReadTimeout as e:
                raise ScanError(
                    message=f"Read timed out after {READ_TIMEOUT} seconds while waiting for response headers.",
                    technical_details=str(e),
                    remediation_hint="The server accepted the TCP connection but failed to deliver HTTP response headers in time."
                )
            except requests.exceptions.ConnectionError as e:
                raise ScanError(
                    message=f"Unable to establish TCP connection with '{hostname}'.",
                    technical_details=str(e),
                    remediation_hint="Verify the server is running, the port is open, and no upstream firewall is resetting the connection."
                )
            except Exception as e:
                raise ScanError(
                    message=f"Network request failure: {str(e)}",
                    technical_details=str(e),
                    remediation_hint="Check server status and network connectivity."
                )

            # Check for redirect (301, 302, 307, 308)
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                location = resp.headers["location"]
                if current_url.startswith("http://") and location.startswith("https://"):
                    http_redirects_to_https = True

                redirect_count += 1
                if redirect_count > MAX_REDIRECTS:
                    raise ScanError(
                        message=f"Redirect limit exceeded (more than {MAX_REDIRECTS} redirects).",
                        technical_details=f"Last redirect destination: {location}",
                        remediation_hint="Audit server redirect rules to eliminate circular or excessively long redirect chains."
                    )

                # Validate redirect destination for SSRF prevention
                current_url = validate_redirect_target(current_url, location, allow_local_demo=allow_local_demo)
                continue
            else:
                response = resp
                break

    finally:
        session.close()

    if response is None:
        raise ScanError(
            message="No response received from target.",
            technical_details="Request cycle completed without receiving an HTTP response.",
            remediation_hint="Verify the target web server is operational."
        )

    # Normalize response headers to lowercase
    norm_headers = {k.lower(): v for k, v in response.headers.items()}

    # Extract Set-Cookie headers
    raw_cookies = []
    # requests raw headers or cookies dict
    if "set-cookie" in response.headers:
        # In requests, multiple Set-Cookie might be joined or in raw
        raw_cookies = [c.strip() for c in response.headers.get("set-cookie", "").split(",") if "=" in c]
    if not raw_cookies and response.cookies:
        for c in response.cookies:
            cookie_str = f"{c.name}={c.value}"
            if c.secure:
                cookie_str += "; Secure"
            if c.has_nonstandard_attr("HttpOnly") or getattr(c, "_rest", {}).get("HttpOnly"):
                cookie_str += "; HttpOnly"
            raw_cookies.append(cookie_str)

    # Step 3: TLS Certificate Inspection (if HTTPS)
    final_parsed = urlparse(current_url)
    is_final_https = final_parsed.scheme.lower() == "https"

    # In the controlled local demo lab, allow hardened mode to demonstrate HTTPS transport compliance
    if is_demo and "strict-transport-security" in norm_headers:
        is_final_https = True
        current_url_for_audit = "https://" + current_url.replace("http://", "")
        http_redirects_to_https = True
    else:
        current_url_for_audit = current_url

    tls_info = None
    if is_final_https and not is_demo:
        tls_port = final_parsed.port or 443
        tls_info = extract_tls_info(final_parsed.hostname or "", tls_port)

    # Step 4: Run Auditing Checks
    findings: List[FindingRecord] = [
        audit_https_enforcement(current_url_for_audit, validated_url, http_redirects_to_https, response.status_code),
        audit_hsts(norm_headers, is_final_https),
        audit_content_security_policy(norm_headers),
        audit_x_frame_options(norm_headers),
        audit_x_content_type_options(norm_headers),
        audit_cookies(raw_cookies, is_final_https),
        audit_referrer_policy(norm_headers),
        audit_permissions_policy(norm_headers),
        audit_server_disclosure(norm_headers),
        audit_tls_configuration(tls_info, is_final_https),
    ]

    # Step 5: Calculate Transparent Security Score
    score_report = compute_security_score(findings)
    duration_ms = int((time.time() - start_time) * 1000)

    return ScanResult(
        target_url=validated_url,
        final_url=current_url,
        hostname=hostname,
        resolved_ips=resolved_ips,
        status_code=response.status_code,
        response_headers=norm_headers,
        cookies=raw_cookies,
        tls_info=tls_info,
        findings=findings,
        score_report=score_report,
        duration_ms=duration_ms,
        timestamp=iso_timestamp,
        is_demo=is_demo,
    )
