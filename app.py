"""GOVNEXIS 3.0 — Platform Entry Point (Flask).

Intelligent Government Web Security Auditing Platform.
Tagline: "See the Risk. Fix the Gap. Build Trust."
Version: 3.0.0
"""

import os
import sys

# Ensure application directory is in python module path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app
from config import APP_NAME, APP_VERSION, APP_TAGLINE, LOCAL_DEMO_URL

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    print("=" * 70)
    print(f" {APP_NAME} (v{APP_VERSION}) — Native Flask Platform")
    print(f" Tagline: \"{APP_TAGLINE}\"")
    print("=" * 70)
    print(f" * Web Application: http://{host}:{port}/")
    print(f" * Isolated Local Sandbox: {LOCAL_DEMO_URL}")
    print(f" * Navigation Order: 1. New Scan | 2. Overview | 3. Findings | 4. Remediation")
    print(f"                     5. Verification | 6. History | 7. Reports | 8. Demo Lab | 9. Settings")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)
