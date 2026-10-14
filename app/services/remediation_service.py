"""Remediation Tracking and Technical Playbook Service for GOVNEXIS 3.0."""

from typing import Dict, List, Any, Optional
from app.database.db import get_remediation_tasks, update_remediation_status, get_distinct_hosts

ALLOWED_STATUSES = ["Open", "In Progress", "Fixed", "Verified"]

# Technical configuration playbooks for security headers and hardening
PLAYBOOKS: Dict[str, Dict[str, str]] = {
    "https_enforced": {
        "title": "HTTPS Transport Enforcement",
        "nginx": "server {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    server_name _;\n    return 301 https://$host$request_uri;\n}",
        "apache": "<VirtualHost *:80>\n    RewriteEngine On\n    RewriteCond %{HTTPS} off\n    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n</VirtualHost>",
        "caddy": "# Caddy automatically enforces HTTPS and redirect for all declared domains.",
    },
    "hsts_header": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
        "caddy": "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
    },
    "content_security_policy": {
        "title": "Content-Security-Policy (CSP)",
        "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\" always;",
        "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"",
        "caddy": "header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\"",
    },
    "x_frame_options": {
        "title": "Clickjacking Defense (X-Frame-Options)",
        "nginx": "add_header X-Frame-Options \"DENY\" always;",
        "apache": "Header always set X-Frame-Options \"DENY\"",
        "caddy": "header X-Frame-Options \"DENY\"",
    },
    "x_content_type_options": {
        "title": "MIME-Sniffing Defense (X-Content-Type-Options)",
        "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
        "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        "caddy": "header X-Content-Type-Options \"nosniff\"",
    },
    "secure_cookies": {
        "title": "Cookie Security Attributes",
        "nginx": "proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;",
        "apache": "Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
        "caddy": "# Configure flags in backend application cookie creation session handlers.",
    },
    "referrer_policy": {
        "title": "Referrer-Policy Header",
        "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "caddy": "header Referrer-Policy \"strict-origin-when-cross-origin\"",
    },
    "permissions_policy": {
        "title": "Permissions-Policy Header",
        "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
        "apache": "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"",
        "caddy": "header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"",
    },
    "server_disclosure": {
        "title": "Server Information Disclosure",
        "nginx": "server_tokens off;",
        "apache": "ServerTokens Prod\nServerSignature Off",
        "caddy": "# Caddy does not advertise Server header version numbers by default.",
    },
    "tls_configuration": {
        "title": "TLS Protocol & Certificate Hygiene",
        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;",
        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite HIGH:!aNULL:!MD5",
        "caddy": "# Caddy enforces modern TLSv1.2 and TLSv1.3 by default.",
    },
}


class RemediationService:
    """Service layer managing remediation lifecycles and configuration playbooks."""

    @staticmethod
    def list_tasks(target_host: Optional[str] = None, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve remediation tasks with optional filtering."""
        return get_remediation_tasks(target_host=target_host, status_filter=status_filter)

    @staticmethod
    def get_hosts() -> List[str]:
        """Retrieve unique target hosts with remediation tasks."""
        return get_distinct_hosts()

    @staticmethod
    def update_task(task_id: int, new_status: str, notes: str = "") -> bool:
        """Update remediation task state with strict validation."""
        if new_status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid state '{new_status}'. Allowed states: {', '.join(ALLOWED_STATUSES)}")
        return update_remediation_status(task_id=task_id, new_status=new_status, notes=notes)

    @staticmethod
    def get_playbook(check_id: str) -> Optional[Dict[str, str]]:
        """Retrieve remediation code snippets for a check ID."""
        return PLAYBOOKS.get(check_id)
