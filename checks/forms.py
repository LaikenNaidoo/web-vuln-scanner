from urllib.parse import urlparse
from bs4 import BeautifulSoup


def check_forms(response):
    findings = []
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    page_scheme = urlparse(response.url).scheme

    for idx, form in enumerate(forms, start=1):
        action = form.get("action", "").strip()
        method = form.get("method", "GET").upper()
        inputs = form.find_all("input")

        has_password = any(inp.get("type", "").lower() == "password" for inp in inputs)
        if has_password and (page_scheme == "http" or action.startswith("http://")):
            findings.append({
                "id": f"FORM-INSECURE-AUTH-{idx}",
                "category": "Cryptographic Failures",
                "title": f"Password Form Transmitted Over Unencrypted HTTP (Form #{idx})",
                "severity": "High",
                "evidence": f"Form action='{action or response.url}' on scheme '{page_scheme}'",
                "impact": "Credentials submitted through this form can be intercepted in cleartext on the network.",
                "remediation": "Serve all authentication forms exclusively over HTTPS and update form action URLs.",
            })

        if method == "POST":
            token_names = ("csrf", "xsrf", "token", "_token", "authenticity_token")
            has_csrf = any(
                any(tok in (inp.get("name", "").lower() + inp.get("id", "").lower()) for tok in token_names)
                for inp in inputs
            )
            if not has_csrf:
                findings.append({
                    "id": f"FORM-NO-CSRF-TOKEN-{idx}",
                    "category": "Cross-Site Request Forgery (CSRF)",
                    "title": f"POST Form Missing Anti-CSRF Token Field (Form #{idx})",
                    "severity": "Medium",
                    "evidence": f"POST form (action='{action or 'self'}') contains no recognizable hidden anti-CSRF input.",
                    "impact": "State-changing requests may be vulnerable to forged cross-site submissions if SameSite cookies are not enforced.",
                    "remediation": "Include an unpredictable per-session anti-CSRF token in all state-changing POST forms and set SameSite=Lax/Strict on session cookies.",
                })

    return findings
