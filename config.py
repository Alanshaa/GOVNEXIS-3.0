"""GOVNEXIS 3.0 — Configuration and Constants.

Intelligent Government Web Security Auditing Platform.
Tagline: "See the Risk. Fix the Gap. Build Trust."
Version: 3.0.0
"""

import os
from typing import Dict, Any

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

APP_NAME = "GOVNEXIS 3.0"
APP_VERSION = "3.0.0"
APP_CATEGORY = "Government Website Security Configuration Auditing Platform"
APP_TAGLINE = "See the Risk. Fix the Gap. Build Trust."
APP_DESCRIPTION = (
    "GOVNEXIS 3.0 helps authorized website owners identify security configuration weaknesses, "
    "understand their impact, prioritize remediation, and verify improvements through "
    "repeatable security checks."
)
AUTHOR = "GOVNEXIS Security Engineering Team"

# Local Demo Server Configuration
LOCAL_DEMO_HOST = os.environ.get("LOCAL_DEMO_HOST", "127.0.0.1")
LOCAL_DEMO_PORT = int(os.environ.get("LOCAL_DEMO_PORT", "8765"))
LOCAL_DEMO_URL = f"http://{LOCAL_DEMO_HOST}:{LOCAL_DEMO_PORT}"

# Scanner Constraints & Defensive Guards
CONNECT_TIMEOUT = float(os.environ.get("SCAN_CONNECT_TIMEOUT", "5.0"))  # seconds
READ_TIMEOUT = float(os.environ.get("SCAN_READ_TIMEOUT", "8.0"))        # seconds
MAX_REDIRECTS = int(os.environ.get("SCAN_MAX_REDIRECTS", "5"))         # redirect hop limit
MAX_RESPONSE_BYTES = 2097152                                           # 2 MB response size cap
SCAN_USER_AGENT = "GOVNEXIS-Security-Auditor/3.0.0 (Defensive-Audit-Platform; Authorized-Use-Only)"

# Result Statuses
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_WARNING = "WARNING"
STATUS_NOT_ASSESSED = "NOT ASSESSED"

# Severity Categories
SEV_CRITICAL = "Critical"
SEV_HIGH = "High"
SEV_MEDIUM = "Medium"
SEV_LOW = "Low"
SEV_INFO = "Informational"

# Transparent Security Scoring Weights (Sum = 100)
# Based on CISA BOD 18-01, NIST SP 800-52r2, and OWASP Secure Headers Project
CHECK_WEIGHTS: Dict[str, Dict[str, Any]] = {
    "https_enforced": {
        "title": "HTTPS Transport Enforcement",
        "weight": 20,
        "severity_on_fail": SEV_CRITICAL,
        "category": "Transport Layer Security",
        "description": "Verifies that communication requires TLS encryption to prevent eavesdropping and tampering.",
        "standard_reference": "CISA BOD 18-01 / NIST SP 800-52 Rev. 2",
    },
    "hsts_header": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "weight": 15,
        "severity_on_fail": SEV_HIGH,
        "category": "Transport Layer Security",
        "description": "Checks for Strict-Transport-Security with max-age >= 1 year and includeSubDomains.",
        "standard_reference": "CISA BOD 18-01 / RFC 6797",
    },
    "content_security_policy": {
        "title": "Content-Security-Policy (CSP)",
        "weight": 15,
        "severity_on_fail": SEV_HIGH,
        "category": "Injection Defense",
        "description": "Inspects CSP directives to mitigate Cross-Site Scripting (XSS) and code injection.",
        "standard_reference": "W3C CSP Level 3 / OWASP Top 10",
    },
    "x_frame_options": {
        "title": "Clickjacking Defense (X-Frame-Options / frame-ancestors)",
        "weight": 10,
        "severity_on_fail": SEV_MEDIUM,
        "category": "UI Redressing",
        "description": "Ensures the site prevents embedding in hostile iframes via X-Frame-Options or CSP frame-ancestors.",
        "standard_reference": "RFC 7034 / OWASP Clickjacking Defense Cheat Sheet",
    },
    "x_content_type_options": {
        "title": "MIME-Sniffing Defense (X-Content-Type-Options)",
        "weight": 10,
        "severity_on_fail": SEV_MEDIUM,
        "category": "Content Handling",
        "description": "Requires 'nosniff' to prevent browsers from interpreting non-executable MIME types as executable.",
        "standard_reference": "Fetch Living Standard / OWASP Secure Headers",
    },
    "secure_cookies": {
        "title": "Cookie Security Attributes (Secure, HttpOnly, SameSite)",
        "weight": 10,
        "severity_on_fail": SEV_MEDIUM,
        "category": "Session Integrity",
        "description": "Audits Set-Cookie headers for Secure flag, HttpOnly flag, and appropriate SameSite controls.",
        "standard_reference": "RFC 6265bis / OWASP Session Management Cheat Sheet",
    },
    "referrer_policy": {
        "title": "Referrer-Policy Header",
        "weight": 5,
        "severity_on_fail": SEV_LOW,
        "category": "Information Disclosure",
        "description": "Restricts URL path and parameter leakage in Referer headers to third-party destinations.",
        "standard_reference": "W3C Referrer Policy / OWASP Secure Headers",
    },
    "permissions_policy": {
        "title": "Permissions-Policy Header",
        "weight": 5,
        "severity_on_fail": SEV_LOW,
        "category": "Feature Governance",
        "description": "Disables unnecessary browser hardware features (camera, microphone, geolocation) by default.",
        "standard_reference": "W3C Permissions Policy / OWASP Defense in Depth",
    },
    "server_disclosure": {
        "title": "Server Information Disclosure",
        "weight": 5,
        "severity_on_fail": SEV_LOW,
        "category": "Information Disclosure",
        "description": "Checks if Server or X-Powered-By headers leak detailed software versions or OS architectures.",
        "standard_reference": "NIST SP 800-123 / OWASP Fingerprinting Guidance",
    },
    "tls_configuration": {
        "title": "TLS Protocol & Certificate Hygiene",
        "weight": 5,
        "severity_on_fail": SEV_LOW,
        "category": "Cryptographic Hygiene",
        "description": "Observes TLS protocol version (>= TLSv1.2 required) and certificate validity window.",
        "standard_reference": "NIST SP 800-52 Rev. 2 / CISA Guidance",
    },
}

# Database File Path
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "govnexis.db")
DATABASE_PATH = os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


class Config:
    """Base Flask configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "govnexis-dev-secret-key-change-in-production-2026")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # No premature timeout for long scan workflows
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max request payload
    EXPORTS_DIR = os.path.join(BASE_DIR, "exports")
    DATA_DIR = os.path.join(BASE_DIR, "data")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    # Ensure production uses an environment-provided secret key
    SECRET_KEY = os.environ.get("SECRET_KEY", "govnexis-production-fallback-key-3.0")


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    DATABASE_PATH = ":memory:"


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
