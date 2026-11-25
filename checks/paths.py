from urllib.parse import urljoin
import requests

SENSITIVE_PATHS = [
    (".env", "High", "Environment configuration file containing API keys, DB credentials, or secrets."),
    (".git/HEAD", "High", "Exposed Git repository metadata allowing full source code reconstruction."),
    ("backup.zip", "High", "Unprotected archive backup potentially containing source code or database dumps."),
    ("phpinfo.php", "Medium", "PHP diagnostic page exposing server environment variables and paths."),
    ("server-status", "Medium", "Apache status endpoint leaking active requests and internal host details."),
    ("robots.txt", "Info", "Public crawler directives that may reveal hidden administrative routes."),
]


def check_sensitive_paths(base_url, timeout=6):
    findings = []

    for path, severity, description in SENSITIVE_PATHS:
        target = urljoin(base_url.rstrip("/") + "/", path)
        try:
            resp = requests.get(target, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                # Avoid false positives from custom 200 HTML error pages on non-HTML artifacts
                content_type = resp.headers.get("Content-Type", "").lower()
                if path in (".env", ".git/HEAD") and "text/html" in content_type:
                    continue

                findings.append({
                    "id": f"PATH-EXPOSED-{path.upper().replace('.', '').replace('/', '-')}",
                    "category": "Sensitive Data Exposure",
                    "title": f"Accessible Sensitive Resource: /{path}",
                    "severity": severity,
                    "evidence": f"HTTP {resp.status_code} returned for {target} ({len(resp.content)} bytes)",
                    "impact": description,
                    "remediation": f"Restrict public web access to '/{path}' via web server rules or remove it from the web root.",
                })
        except requests.RequestException:
            continue

    return findings
