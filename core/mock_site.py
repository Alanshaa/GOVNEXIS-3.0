"""Local Demo Lab HTTP Server for GOVNEXIS.

Provides an isolated, controlled local test server on 127.0.0.1:8765 to simulate:
- Baseline (vulnerable/misconfigured) state: Missing headers, legacy banners, insecure cookies
- Hardened (compliant) state: Strict HSTS, CSP, XFO, XCTO, modern cookie flags, sanitized banners
- Dynamic state toggling for Before-and-After Hackathon demonstrations
"""

import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional
from core.config import LOCAL_DEMO_HOST, LOCAL_DEMO_PORT


import os

STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".demo_mode")


class MockServerState:
    """Manages the current simulated security posture of the demo server."""
    MODE_BASELINE = "baseline"
    MODE_HARDENED = "hardened"

    def __init__(self):
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        self.httpd: Optional[HTTPServer] = None
        self.lock = threading.Lock()
        self.set_mode(self.MODE_BASELINE)

    def set_mode(self, mode: str):
        with self.lock:
            if mode in (self.MODE_BASELINE, self.MODE_HARDENED):
                try:
                    with open(STATE_FILE, "w") as f:
                        f.write(mode)
                except Exception:
                    pass

    def get_mode(self) -> str:
        with self.lock:
            if os.path.exists(STATE_FILE):
                try:
                    with open(STATE_FILE, "r") as f:
                        content = f.read().strip()
                        if content in (self.MODE_BASELINE, self.MODE_HARDENED):
                            return content
                except Exception:
                    pass
            return self.MODE_BASELINE


# Singleton state instance
DEMO_STATE = MockServerState()


class DemoHTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom request handler delivering baseline or hardened response configurations."""
    server_version = ""
    sys_version = ""

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logging
        return

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())

    def do_GET(self):
        self.handle_response()

    def do_HEAD(self):
        self.handle_response(send_body=False)

    def handle_response(self, send_body: bool = True):
        mode = DEMO_STATE.get_mode()

        if mode == MockServerState.MODE_HARDENED:
            # Fully hardened configuration
            status_code = 200
            headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Server": "GOVNEXIS-SecureGateway",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
                "Set-Cookie": "gov_session=s7f289d0a1b8c4e; Secure; HttpOnly; SameSite=Lax; Path=/",
                "Cache-Control": "no-store, no-cache, must-revalidate",
            }
            body = (
                "<!DOCTYPE html><html><head><title>GOVNEXIS Local Demo (Hardened)</title></head>"
                "<body style='font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;'>"
                "<h1>GOVNEXIS Controlled Demo Target</h1>"
                "<div style='border:1px solid #10b981;padding:1rem;border-radius:8px;background:#064e3b;'>"
                "<h3>Security State: HARDENED</h3>"
                "<p>All recommended defense-in-depth headers and secure cookie attributes are actively enforced.</p>"
                "</div></body></html>"
            ).encode("utf-8")
        else:
            # Baseline misconfigured state (demonstrates common findings)
            status_code = 200
            headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Server": "Apache/2.4.41 (Ubuntu) PHP/7.4.3",
                "X-Powered-By": "PHP/7.4.3",
                "Set-Cookie": "gov_session=s7f289d0a1b8c4e; Path=/",
                # Missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
                # Cookie lacks Secure, HttpOnly, and SameSite flags
            }
            body = (
                "<!DOCTYPE html><html><head><title>GOVNEXIS Local Demo (Baseline)</title></head>"
                "<body style='font-family:sans-serif;background:#18181b;color:#f4f4f5;padding:2rem;'>"
                "<h1>GOVNEXIS Controlled Demo Target</h1>"
                "<div style='border:1px solid #ef4444;padding:1rem;border-radius:8px;background:#450a0a;'>"
                "<h3>Security State: BASELINE (Vulnerable / Misconfigured)</h3>"
                "<p>Missing essential headers (CSP, HSTS, XFO, XCTO) and insecure session cookie configuration.</p>"
                "</div></body></html>"
            ).encode("utf-8")

        self.send_response(status_code)
        for header_name, header_value in headers.items():
            self.send_header(header_name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        if send_body:
            self.wfile.write(body)


def start_mock_server(host: str = LOCAL_DEMO_HOST, port: int = LOCAL_DEMO_PORT) -> bool:
    """Start the local demo HTTP server in a background daemon thread."""
    if DEMO_STATE.running:
        return True

    try:
        httpd = HTTPServer((host, port), DemoHTTPRequestHandler)
        DEMO_STATE.httpd = httpd
        DEMO_STATE.running = True

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        DEMO_STATE.server_thread = thread
        thread.start()
        time.sleep(0.1)  # Allow socket bind
        return True
    except OSError as e:
        # Port might already be in use by another instance
        if "Address already in use" in str(e):
            DEMO_STATE.running = True
            return True
        return False


def stop_mock_server():
    """Stop the local demo server."""
    if DEMO_STATE.httpd and DEMO_STATE.running:
        DEMO_STATE.running = False
        DEMO_STATE.httpd.shutdown()
        DEMO_STATE.httpd.server_close()
        DEMO_STATE.httpd = None


def get_demo_status() -> Dict[str, Any]:
    """Retrieve the current operating status and posture of the demo server."""
    return {
        "running": DEMO_STATE.running,
        "mode": DEMO_STATE.get_mode(),
        "host": LOCAL_DEMO_HOST,
        "port": LOCAL_DEMO_PORT,
        "url": f"http://{LOCAL_DEMO_HOST}:{LOCAL_DEMO_PORT}",
    }
