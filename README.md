# Web Application Security Configuration Auditor

A modular Python CLI security auditing tool that inspects web applications for OWASP security misconfigurations—including missing HTTP security headers, server version disclosure, permissive CORS policies, exposed sensitive files, and insecure HTML forms—and generates structured Markdown and JSON audit reports.

## Project Architecture
- `scanner.py` — Main CLI entry point powered by `argparse`
- `checks/headers.py` — Audits OWASP security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) and server disclosure headers
- `checks/cors.py` — Tests for arbitrary origin reflection and wildcard CORS misconfigurations
- `checks/paths.py` — Checks for publicly accessible sensitive artifacts (`.env`, `.git/HEAD`, backups, `robots.txt`)
- `checks/forms.py` — Parses HTML forms via BeautifulSoup for cleartext HTTP credential submission and missing anti-CSRF tokens
- `reporter.py` — Generates prioritized `AUDIT_REPORT.md` and `audit_report.json` deliverables
- `AUDIT_REPORT.md` — Sample audit report generated against the SauceDemo sandbox

## Installation & Usage
1. Clone the repository: `git clone https://github.com/LaikenNaidoo/web-vuln-scanner.git`
2. Create and activate a virtual environment: `python3 -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run an audit against an authorized target: `python3 scanner.py https://www.saucedemo.com`

## Disclaimer
This tool is built strictly for defensive security auditing, educational labs, and authorized testing against systems you own or have explicit permission to assess.