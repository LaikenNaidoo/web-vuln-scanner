SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Prevents Cross-Site Scripting (XSS) and unauthorized script execution.",
        "Define a strict Content-Security-Policy header restricting script-src and default-src."
    ),
    "Strict-Transport-Security": (
        "High",
        "Enforces HTTPS connections and protects against protocol downgrade attacks.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
    ),
    "X-Frame-Options": (
        "Medium",
        "Protects users against Clickjacking attacks via embedded iframes.",
        "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    ),
    "X-Content-Type-Options": (
        "Low",
        "Stops browsers from MIME-sniffing responses away from declared Content-Type.",
        "Set 'X-Content-Type-Options: nosniff'."
    ),
    "Referrer-Policy": (
        "Low",
        "Controls how much referrer URL information is leaked to external origins.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
    ),
}

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def check_security_headers(response):
    findings = []
    headers = response.headers

    for header, (severity, impact, remediation) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "id": f"HDR-MISSING-{header.upper()}",
                "category": "Security Misconfiguration",
                "title": f"Missing Security Header: {header}",
                "severity": severity,
                "evidence": f"Header '{header}' was not returned by {response.url}",
                "impact": impact,
                "remediation": remediation,
            })

    for header in DISCLOSURE_HEADERS:
        if header in headers:
            findings.append({
                "id": f"HDR-INFO-{header.upper()}",
                "category": "Information Disclosure",
                "title": f"Technology Stack Disclosure via '{header}' Header",
                "severity": "Low",
                "evidence": f"{header}: {headers[header]}",
                "impact": "Reveals exact server/framework versions to aid targeted exploit selection.",
                "remediation": f"Strip or obfuscate the '{header}' response header at the reverse proxy/server level.",
            })

    return findings
