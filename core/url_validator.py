"""URL and Network Safety Validator for GOVNEXIS.

Enforces defensive security controls:
- Scheme validation (http, https only)
- Syntactic verification of hostname and port
- SSRF prevention: blocks loopback, private, link-local, multicast, and reserved IP ranges
- DNS resolution safety and DNS rebinding protections
- Safe redirect destination checking
- Strict allowlisting for the Local Demo Lab
"""

import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from typing import Tuple, List, Optional
from core.config import LOCAL_DEMO_HOST, LOCAL_DEMO_PORT


class ValidationError(Exception):
    """Raised when URL or target validation fails safety or syntax requirements."""
    pass


class SSRFSecurityError(ValidationError):
    """Raised when a URL attempts to target prohibited internal or private infrastructure."""
    pass


def is_ip_prohibited(ip_str: str) -> Tuple[bool, str]:
    """Check if an IP address belongs to private, loopback, link-local, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return True, f"Loopback address ({ip_str}) is prohibited for external scans."
    if ip.is_private:
        return True, f"Private RFC1918/RFC4193 address ({ip_str}) is prohibited."
    if ip.is_link_local:
        return True, f"Link-local address ({ip_str}) is prohibited."
    if ip.is_multicast:
        return True, f"Multicast address ({ip_str}) is prohibited."
    if ip.is_reserved:
        return True, f"Reserved network space ({ip_str}) is prohibited."
    if ip.is_unspecified:
        return True, f"Unspecified 0.0.0.0/:: address ({ip_str}) is prohibited."

    return False, ""


def is_allowed_demo_target(parsed_url) -> bool:
    """Allowlist check strictly for the local controlled demo lab."""
    hostname = parsed_url.hostname or ""
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    
    # Allow localhost / 127.0.0.1 ONLY on the configured demo port
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", LOCAL_DEMO_HOST):
        if port == LOCAL_DEMO_PORT:
            return True
    return False


def validate_and_resolve_url(
    raw_url: str,
    allow_local_demo: bool = False
) -> Tuple[str, List[str]]:
    """Thoroughly validate a target URL for syntax, scheme, and SSRF restrictions.

    Args:
        raw_url: The candidate URL string.
        allow_local_demo: If True, permits targeting localhost on the designated demo port.

    Returns:
        Tuple of (normalized_url, resolved_ips)

    Raises:
        ValidationError or SSRFSecurityError with descriptive plain-English message.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValidationError("URL cannot be empty.")

    cleaned_url = raw_url.strip()
    if "://" not in cleaned_url:
        cleaned_url = "https://" + cleaned_url

    try:
        parsed = urlparse(cleaned_url)
    except Exception as e:
        raise ValidationError(f"Malformatted URL syntax: {str(e)}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValidationError(
            f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL does not contain a valid hostname.")

    if len(hostname) > 253:
        raise ValidationError("Hostname exceeds standard maximum length (253 characters).")

    # Check local demo lab allowlist exception
    if allow_local_demo and is_allowed_demo_target(parsed):
        return cleaned_url, ["127.0.0.1"]

    # If user tries targeting localhost without demo allowlist or on wrong port
    if hostname.lower() in ("localhost", "127.0.0.1", "::1") and not allow_local_demo:
        raise SSRFSecurityError(
            "Loopback targets (localhost / 127.0.0.1) are prohibited in external scanning mode. "
            "Please use the Local Demo Lab for safe sandbox auditing."
        )

    # DNS Resolution and IP Validation to defeat DNS Rebinding
    resolved_ips: List[str] = []
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        raise ValidationError(
            f"DNS resolution failed for '{hostname}'. Verify that the domain exists and is accessible. ({e})"
        )
    except Exception as e:
        raise ValidationError(f"Network resolution error for '{hostname}': {str(e)}")

    if not resolved_ips:
        raise ValidationError(f"Could not resolve any IP addresses for host '{hostname}'.")

    # Validate every resolved IP address
    for ip_str in resolved_ips:
        prohibited, reason = is_ip_prohibited(ip_str)
        if prohibited:
            raise SSRFSecurityError(
                f"Safety restriction triggered: Host '{hostname}' resolves to blocked IP {ip_str}. {reason}"
            )

    return cleaned_url, resolved_ips


def validate_redirect_target(
    current_url: str,
    target_redirect_url: str,
    allow_local_demo: bool = False
) -> str:
    """Safely validate and resolve an HTTP redirect destination before following it."""
    # Resolve relative redirects
    full_redirect_url = urljoin(current_url, target_redirect_url)
    validated_url, _ = validate_and_resolve_url(full_redirect_url, allow_local_demo=allow_local_demo)
    return validated_url
