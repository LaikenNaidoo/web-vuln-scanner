import requests


def check_cors(url, timeout=8):
    findings = []
    evil_origin = "https://evil-attacker.example.com"

    try:
        resp = requests.get(url, headers={"Origin": evil_origin}, timeout=timeout)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil_origin:
            severity = "High" if acac == "true" else "Medium"
            findings.append({
                "id": "CORS-ORIGIN-REFLECTION",
                "category": "Broken Access Control (CORS)",
                "title": "Arbitrary Origin Reflection in CORS Policy",
                "severity": severity,
                "evidence": f"Origin '{evil_origin}' reflected in Access-Control-Allow-Origin (Allow-Credentials: {acac or 'false'})",
                "impact": "Untrusted external sites may read sensitive cross-origin responses from authenticated users.",
                "remediation": "Validate incoming Origin headers against a strict server-side allowlist instead of reflecting arbitrary origins.",
            })
        elif acao == "*" and acac == "true":
            findings.append({
                "id": "CORS-WILDCARD-CREDENTIALS",
                "category": "Broken Access Control (CORS)",
                "title": "Overly Permissive Wildcard CORS Policy",
                "severity": "Medium",
                "evidence": "Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
                "impact": "Exposes cross-origin endpoints broadly to any external domain.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted first-party domains.",
            })
    except requests.RequestException:
        pass

    return findings
