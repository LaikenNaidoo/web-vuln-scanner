import argparse
import sys
import requests

from checks.headers import check_security_headers
from checks.cors import check_cors
from checks.paths import check_sensitive_paths
from checks.forms import check_forms
from reporter import generate_reports


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def run_audit(target_url):
    print(f"\n[*] Starting security configuration audit for: {target_url}")
    try:
        response = requests.get(target_url, timeout=10)
    except requests.RequestException as exc:
        print(f"[!] Failed to connect to {target_url}: {exc}")
        sys.exit(1)

    print(f"[*] Target reachable (HTTP {response.status_code}). Running modular checks...")

    findings = []
    findings.extend(check_security_headers(response))
    findings.extend(check_cors(target_url))
    findings.extend(check_sensitive_paths(target_url))
    findings.extend(check_forms(response))

    generate_reports(target_url, findings)

    print(f"[+] Audit complete. Total findings: {len(findings)}")
    for f in findings:
        print(f"    - [{f['severity'].upper()}] {f['title']}")
    print("\n[+] Reports saved to AUDIT_REPORT.md and audit_report.json\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automated OWASP Security Configuration & Header Auditor"
    )
    parser.add_argument("url", help="Target URL to audit (e.g., https://www.saucedemo.com)")
    args = parser.parse_args()

    run_audit(normalize_url(args.url))