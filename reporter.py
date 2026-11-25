import json
from datetime import datetime, timezone


def generate_reports(target_url, findings, md_path="AUDIT_REPORT.md", json_path="audit_report.json"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    severity_order = {"High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 5))

    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in sorted_findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    report_data = {
        "target": target_url,
        "scanned_at": timestamp,
        "summary": counts,
        "total_findings": len(sorted_findings),
        "findings": sorted_findings,
    }
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(report_data, jf, indent=2)

    lines = [
        "# Web Application Security Configuration Audit Report",
        "",
        f"- **Target URL:** `{target_url}`",
        f"- **Scan Timestamp:** {timestamp}",
        f"- **Total Findings:** {len(sorted_findings)} (High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}, Info: {counts['Info']})",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "| :--- | :--- |",
        f"| High | {counts['High']} |",
        f"| Medium | {counts['Medium']} |",
        f"| Low | {counts['Low']} |",
        f"| Info | {counts['Info']} |",
        "",
        "---",
        "",
        "## Detailed Findings & Remediation",
        "",
    ]

    if not sorted_findings:
        lines.append("No configuration issues or missing security headers were detected.")
    else:
        for idx, item in enumerate(sorted_findings, start=1):
            lines.extend([
                f"### {idx}. [{item['severity'].upper()}] {item['title']} (`{item['id']}`)",
                f"- **Category:** {item['category']}",
                f"- **Evidence:** `{item['evidence']}`",
                f"- **Security Impact:** {item['impact']}",
                f"- **Recommended Remediation:** {item['remediation']}",
                "",
            ])

    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write("\n".join(lines))