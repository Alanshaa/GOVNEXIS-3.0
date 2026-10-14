# GOVNEXIS 3.0 — Government Website Security Configuration Auditing Platform

> **"See the Risk. Fix the Gap. Build Trust."**  
> *Platform Version:* **3.0.0** | *Engine:* **Python / Flask / SQLite / Jinja2 / Chart.js**

---

## 1. Project Overview & Mission

**GOVNEXIS 3.0** is an enterprise-grade, independently runnable website security configuration auditing platform specifically engineered for government, municipal, and critical infrastructure web properties. 

Rather than relying on intrusive vulnerability fuzzing or destructive attack vectors, GOVNEXIS 3.0 performs rigorous, passive, defensive assessments of public HTTP response headers, cookie flags, and Transport Layer Security (TLS) handshake parameters. It translates technical findings into actionable remediation guidance, calculates deterministic **Configuration Compliance Scores (0–100)**, evaluates vulnerability severity using the **official FIRST Common Vulnerability Scoring System (CVSS) v3.0** methodology, and scientifically proves risk reduction via empirical **Before-and-After Verification**.

GOVNEXIS 3.0 has been re-architected from the ground up as a native **Flask web application**, replacing the legacy Streamlit interface with a high-performance, modular Blueprint architecture, separated service layers, parameterized SQLite persistence, and a custom cybersecurity operations interface.

---

## 2. Platform Architecture

```
govnexis3.0/
├── run.py                     # Primary Flask application entry point
├── app.py                     # Alternate CLI & development entry point
├── config.py                  # Environment-separated configuration (Dev, Prod, Test)
├── requirements.txt           # Minimal, locked production dependencies
├── .env.example               # Deployment environment variables template
├── .gitignore                 # Repository exclusions
├── README.md                  # Comprehensive platform documentation
├── app/                       # Application Package
│   ├── __init__.py            # Flask application factory (create_app) & security headers
│   ├── extensions.py          # Flask-WTF CSRF protection
│   ├── routes/                # Modular Flask Blueprints (Exact navigation order)
│   │   ├── __init__.py
│   │   ├── scanner.py         # 1. New Scan route & execution handler (/scan)
│   │   ├── main.py            # 2. Executive Overview & trends (/overview)
│   │   ├── findings.py        # 3. Interactive Findings Center (/findings)
│   │   ├── remediation.py     # 4. Remediation checklist & task tracking (/remediation)
│   │   ├── verification.py    # 5. Before-and-After empirical comparison (/verification)
│   │   ├── history.py         # 6. SQLite-backed historical audit table (/history)
│   │   ├── reports.py         # 7. Multi-format export engine (/reports)
│   │   ├── demo_lab.py        # 8. Controlled sandbox simulation harness (/demo-lab)
│   │   └── settings.py        # 9. Standards mappings, scanner limits & maintenance (/settings)
│   ├── services/              # Business Logic & Service Layer
│   │   ├── __init__.py
│   │   ├── scanner_service.py # Orchestrates SSRF checks & network audit dispatch
│   │   ├── security_checks.py # 10 rule evaluators (HSTS, CSP, XFO, cookies, etc.)
│   │   ├── cvss.py            # Official FIRST CVSS v3.0 equations, rounding & vectors
│   │   ├── scoring.py         # Weighted configuration score (0-100) and letter grading
│   │   ├── remediation_service.py # Lifecycle state transitions & server playbooks
│   │   ├── verification_service.py # Differential audit delta calculations
│   │   └── report_service.py  # ReportLab PDF, HTML, JSON, and CSV exports
│   ├── database/              # Persistence Layer
│   │   ├── __init__.py
│   │   ├── db.py              # Parameterized SQLite queries, migrations & CRUD
│   │   └── schema.sql         # Database schema definitions & indexing
│   ├── templates/             # Responsive Jinja2 Templates
│   │   ├── base.html          # Base layout, dark theme, sidebar & CSRF tokens
│   │   ├── dashboard.html     # Executive charts & metrics
│   │   ├── scanner.html       # URL entry, live progress bar & results summary
│   │   ├── findings.html      # Multi-parameter filterable finding accordions
│   │   ├── remediation.html   # Task management & server hardening snippets
│   │   ├── verification.html  # Empirical baseline vs rescan comparison
│   │   ├── history.html       # Stored audit trail with search & pagination
│   │   ├── reports.html       # Document previews & direct download triggers
│   │   ├── demo_lab.html      # Local sandbox harness controls (127.0.0.1:8765)
│   │   ├── settings.html      # CISA/NIST/OWASP reference matrix & troubleshooting
│   │   ├── 404.html           # Defensive 404 resource not found page
│   │   └── 500.html           # Server error fallback template
│   └── static/                # Modern Frontend Assets
│       ├── css/
│       │   └── style.css      # Custom cybersecurity operations design system
│       └── js/
│           └── app.js         # Interactive client logic, Chart.js & CSRF headers
├── core/                      # Backward-compatible framework-independent engine
├── tests/                     # Automated Test Suite (80 passing tests)
├── data/                      # Local data artifacts
└── exports/                   # Export staging directory
```

---

## 3. Required Navigation Hierarchy

GOVNEXIS 3.0 strictly maintains a uniform 9-page navigation structure across all routes:

1. **New Scan** (`/scan`): Single-target audit launcher, authorization checkbox, presets, live progress feedback, and instant results summary.
2. **Overview** (`/overview`): Executive cybersecurity operations dashboard with Chart.js CVSS distribution, trend lines, category bars, and recent audit activity.
3. **Findings** (`/findings`): Interactive findings explorer supporting multi-parameter filtering (by severity, status, category, host) and collapsible technical evidence drawers.
4. **Remediation** (`/remediation`): Lifecycle task tracker (`Open` → `In Progress` → `Fixed` → `Verified`) with web server hardening playbooks (Nginx, Apache, Caddy).
5. **Verification** (`/verification`): Empirical comparison between two stored scans, displaying score deltas, CVSS reduction, resolved findings, and response header diffs.
6. **History** (`/history`): Searchable, paginated audit records with detailed inspection, report triggers, and single/batch deletion controls.
7. **Reports** (`/reports`): In-browser interactive preview (HTML, JSON, CSV) and direct one-click downloads for PDF, HTML, JSON, and CSV.
8. **Demo Lab** (`/demo-lab`): Air-gapped sandbox on `127.0.0.1:8765` demonstrating Baseline (misconfigured) vs. Hardened (compliant) security postures.
9. **Settings** (`/settings`): Federal compliance standards cross-reference matrix, scanner engine constraints, guided troubleshooting, and database maintenance tools.

---

## 3.1 GOVNEXIS 3.0 | NEXION Updated Design System

GOVNEXIS 3.0 incorporates the modern **NEXION** brand identity:

- **Primary Brand Purple:** `#8B5CF6` (Dark) / `#7047D9` (Light)
- **Dark Mode Surfaces:** Main Background `#17171D`, Secondary `#1D1D26`, Cards `#242430`, Elevated Panels `#2C2C39`, Text `#F4F4F8`, Muted `#A5A5B5`, Border `#383846`.
- **Light Mode Surfaces (Default):** Main Background `#F5F5F8`, Card `#FFFFFF`, Secondary `#EBEBF2`, Primary Text `#20202B`, Muted `#666675`, Border `#DEDEE8`.
- **Persistent Light / Dark Mode Toggle:** First-time visitors see crisp Light Mode by default. The header theme switch saves preferences to browser local storage (`govnexis-theme`), dynamically adjusts Chart.js color schemes, and prevents Flash of Unstyled Content (FOUC).
- **Iconography & Polish:** Strictly **zero emojis** across all pages; uses crisp, inline SVG geometry and distinct severity tokens (Critical Red, High Orange, Medium Amber, Low Blue, Pass Emerald).
- **Brand Logo:** Preserves the original NEXION silver-and-teal emblem in the navigation sidebar with crisp proportional scaling.

---

## 4. Supported Security Controls & Federal Standards

GOVNEXIS 3.0 evaluates 10 core configuration rules grounded directly in federal and international standards:

| # | Security Control | Weight | Severity on Failure | Reference Standard | Assessment Nature |
|---|------------------|--------|---------------------|--------------------|-------------------|
| 1 | **HTTPS Transport Enforcement** | 20 pts | **Critical** | CISA BOD 18-01 / NIST SP 800-52r2 | Technical Vulnerability |
| 2 | **HTTP Strict Transport Security (HSTS)** | 15 pts | **High** | CISA BOD 18-01 / RFC 6797 | Technical Vulnerability |
| 3 | **Content-Security-Policy (CSP)** | 15 pts | **High** | W3C CSP Level 3 / OWASP Top 10 | Technical Vulnerability |
| 4 | **Clickjacking Defense (X-Frame-Options)** | 10 pts | **Medium** | RFC 7034 / OWASP Cheat Sheet | Technical Vulnerability |
| 5 | **MIME-Sniffing Defense (X-Content-Type-Options)** | 10 pts | **Medium** | Fetch Living Standard / OWASP | Configuration Hygiene |
| 6 | **Cookie Security Flags (Secure, HttpOnly, SameSite)** | 10 pts | **Medium** | RFC 6265bis / OWASP Session Guide | Technical Vulnerability |
| 7 | **Referrer-Policy Header** | 5 pts | **Low** | W3C Referrer Policy / OWASP | Configuration Hygiene |
| 8 | **Permissions-Policy Header** | 5 pts | **Low** | W3C Permissions Policy / OWASP | Configuration Hygiene |
| 9 | **Server Information Disclosure (Banner Leakage)** | 5 pts | **Low** | NIST SP 800-123 / OWASP Fingerprint | Configuration Hygiene |
| 10 | **TLS Protocol & Certificate Hygiene** | 5 pts | **Low** | NIST SP 800-52 Rev. 2 / CISA | Cryptographic Hygiene |

---

## 5. CVSS v3.0 Scoring Methodology & Limitations

GOVNEXIS 3.0 implements the official FIRST Common Vulnerability Scoring System (CVSS) v3.0 Base Score methodology:

- **Mathematical Fidelity:** Employs official CVSS v3.0 exploitability equations, Scope transition adjustments, and the official `Roundup` ceiling function.
- **Defensible Vector Strings:** Generates valid vectors conforming to `CVSS:3.0/AV:N/AC:L/...`.
- **Hygiene Findings Marked "Not Scored":** Findings that represent defense-in-depth configuration hygiene without a confirmed, direct exploit vector (e.g., absence of `Permissions-Policy` or `Referrer-Policy`) are explicitly classified as **Not Scored**.
- **Vulnerability vs. Rating Distinction:** CVSS measures *vulnerability severity*, not a comprehensive website health rating. GOVNEXIS 3.0 maintains a dual-score presentation:
  1. **Configuration Compliance Score (0–100):** Reflects alignment with CISA BOD 18-01 and NIST guidelines.
  2. **CVSS v3.0 Base Score (0.0–10.0):** Reflects the maximum exploitable risk rating among evaluated findings.

---

## 6. Defensive Safety & SSRF Protections

To protect internal infrastructure and prevent server-side request forgery (SSRF), GOVNEXIS 3.0 enforces strict safety boundaries:

1. **Protocol Whitelisting:** Permits only standard `http://` and `https://` schemes.
2. **SSRF Guard:** Resolves destination hostnames via DNS and blocks loopback (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`), and unspecified addresses (`0.0.0.0`).
3. **Redirect Destination Checking:** Resolves every hop in an HTTP 3xx redirect chain before following, preventing redirect-based perimeter evasion.
4. **Single-Port Sandbox Exception:** The Local Demo Lab (`127.0.0.1:8765`) is governed by an explicit single-port exception. Scans to localhost on any other port (e.g., port 80, 8080, 3000) are unconditionally blocked.
5. **Strict TLS Enforcement:** TLS certificate verification is never disabled during external production audits.
6. **Defensive Resource Caps:** Sockets enforce a 5.0s connection timeout, 8.0s read timeout, 5 max redirect hops, and a 2 MB response size cap.
7. **Mandatory User Authorization:** The scanning engine enforces user-certified written authorization prior to audit execution.

---

## 7. Installation & Setup Instructions

### Linux (Compatible with Kali Linux & Arch Linux)

```bash
# 1. Navigate to project root
cd govnexis3.0

# 2. Create and activate isolated Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip to latest release
python3 -m pip install --upgrade pip

# 4. Install locked dependencies
pip install -r requirements.txt

# 5. Copy environment template
cp .env.example .env

# 6. Start GOVNEXIS 3.0
python run.py
```

### Windows (PowerShell)

```powershell
# 1. Navigate to project root
cd "C:\Users\MUGIL\OneDrive\Desktop\GOVNEXIS 3.0"

# 2. Create and activate virtual environment (if needed)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install requirements
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Copy environment configuration
Copy-Item .env.example .env

# 5. Launch GOVNEXIS 3.0
python run.py
```

Upon launching, the Flask application will be accessible at:
👉 **`http://127.0.0.1:5000/`**

The isolated Demo Sandbox daemon will be online at:
👉 **`http://127.0.0.1:8765/`**

---

## 8. Running the Automated Test Suite

GOVNEXIS 3.0 includes an exhaustive test suite covering unit calculations, persistence, SSRF boundaries, reports, and Flask route rendering:

```bash
# Run complete test suite
python -m pytest tests

# Run with verbose test step reporting
python -m pytest tests -v
```

**Verification Results:**
- **80 Tests Collected**
- **80 Passed (100% Success Rate)**
- **0 Failed, 0 Skipped**

---

## 9. Local Demo Lab Workflow (Hackathon & Sandbox Guide)

The built-in demo lab enables repeatable live demonstration of web security configuration auditing:

1. **Access Sandbox:** Navigate to **8. Demo Lab** (`/demo-lab`). The local sandbox daemon automatically initializes on `127.0.0.1:8765`.
2. **Audit Baseline (Misconfigured State):** Click **Run Baseline Audit**. The engine audits the local sandbox, detecting missing HSTS, missing CSP, missing X-Frame-Options, and insecure cookies (Score: ~50/100, Grade F).
3. **Inspect Findings:** Review the generated findings and CVSS v3.0 base scores in the **Findings Center** (`/findings`).
4. **Track Remediation:** Open **4. Remediation** (`/remediation`) to view the auto-generated checklist items. Update task status from `Open` to `In Progress` or `Fixed`.
5. **Apply Hardened Posture:** Return to **Demo Lab** and click **Switch to Hardened Mode**. The sandbox activates production-grade security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and secure cookie attributes).
6. **Execute Verification Rescan:** Click **Run Verification Audit**. The rescan confirms compliance (Score: 90+/100, Grade A).
7. **Empirical Before-and-After Analysis:** Navigate to **5. Verification** (`/verification`). Compare the Baseline and Hardened scans to view the +40 pt score improvement, CVSS reduction, and response header diffs.
8. **Export Audit Reports:** Navigate to **7. Reports** (`/reports`) to download executive PDF, HTML, JSON, and CSV reports.

---

## 10. Known Limitations & Defensive Boundaries

1. **Passive Audit Scope:** GOVNEXIS 3.0 assesses public HTTP response headers, cookie flags, and TLS protocol observations. It does not perform invasive vulnerability scanning, SQL injection exploitation, authenticated credential brute-forcing, or binary memory analysis.
2. **Reverse Proxy Masking:** Websites deployed behind third-party CDN or cloud proxy layers (e.g., Cloudflare, Akamai, CloudFront) reflect the outer proxy's TLS ciphers and public headers, which may differ from the origin server's direct configuration.
3. **Single Page Audit:** The scanner inspects the target root landing page and redirects. Deep web crawling across authenticated enterprise portals is intentionally out of scope for passive configuration governance.

---

## 11. Future Roadmap

- Automated recurring scan scheduling via cron/celery workers.
- Integration with external SIEM webhooks (Splunk, Elastic, Microsoft Sentinel).
- SAML 2.0 / OIDC single sign-on authentication for multi-tenant municipal agencies.
- Subdomain enumeration and automated perimeter discovery for authorized domains.

---

## 12. License & Ethical Disclaimer

**Defensive & Authorized Use Only:** GOVNEXIS 3.0 is designed exclusively for authorized system administrators, security auditors, and government agency web owners. Scanning targets without explicit authorization is strictly prohibited under applicable computer crime and cybersecurity statutes.
