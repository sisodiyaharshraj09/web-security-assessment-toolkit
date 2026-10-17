#!/usr/bin/env python3
"""
Web Security Assessment Toolkit
A beginner-friendly, non-intrusive checker for security headers and cookie flags.

Use only against localhost, systems you own, or targets you have explicit
written permission to assess. This tool makes one GET request and does not
crawl, exploit, brute-force, or submit forms.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

CHECKS = {
    "Content-Security-Policy": {
        "severity": "Informational",
        "recommendation": "Consider a Content-Security-Policy suited to the application's resources."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Set X-Content-Type-Options: nosniff where appropriate."
    },
    "Referrer-Policy": {
        "severity": "Informational",
        "recommendation": "Set a Referrer-Policy that limits unnecessary referrer information."
    },
    "Permissions-Policy": {
        "severity": "Informational",
        "recommendation": "Consider restricting browser features the application does not need."
    },
    "Strict-Transport-Security": {
        "severity": "Low",
        "recommendation": "For HTTPS sites, consider HSTS after confirming all relevant subdomains support HTTPS."
    },
}

def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("Do not place credentials in the URL.")
    host = parsed.hostname.lower()
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if host not in local_hosts:
        print(
            "\nAUTHORIZATION CHECK:\n"
            "Only continue if you own this target or have explicit permission to test it.\n"
            "This tool sends one GET request and does not attempt exploitation.\n"
        )
        answer = input(f"Do you have permission to assess {host}? Type YES to continue: ").strip()
        if answer != "YES":
            raise PermissionError("Stopped because authorization was not confirmed.")
    return url

def assess(url: str, timeout: float = 8.0) -> dict:
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "WebSecurityAssessmentToolkit/1.0 (educational; non-intrusive)"},
    )
    headers = {k: v for k, v in response.headers.items()}
    findings = []

    for header, details in CHECKS.items():
        present = header in response.headers
        findings.append({
            "title": f"{header} {'present' if present else 'not observed'}",
            "category": "Security headers",
            "severity": "Informational" if present else details["severity"],
            "status": "Observed" if present else "Review recommended",
            "evidence": f"{header}: {response.headers.get(header, '(not present in response)')}",
            "recommendation": "Review the value for suitability." if present else details["recommendation"],
            "limitation": "Header presence alone does not prove an application is secure or vulnerable."
        })

    set_cookie_values = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not set_cookie_values:
        # requests combines duplicate headers on some adapters; this is a best-effort check.
        single = response.headers.get("Set-Cookie")
        set_cookie_values = [single] if single else []

    if set_cookie_values:
        for idx, cookie in enumerate(set_cookie_values, start=1):
            lower = cookie.lower()
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            findings.append({
                "title": f"Cookie {idx} attribute review",
                "category": "Cookie configuration",
                "severity": "Low" if missing else "Informational",
                "status": "Review recommended" if missing else "Observed",
                "evidence": f"Set-Cookie: {cookie}",
                "recommendation": (
                    "Review whether these attributes are appropriate: " + ", ".join(missing) + "."
                    if missing else "Review cookie scope and attributes for the application's threat model."
                ),
                "limitation": "Cookie requirements depend on how the cookie is used; this is a heuristic, not a definitive vulnerability verdict."
            })

    if urlparse(url).scheme != "https":
        findings.append({
            "title": "Target URL uses HTTP",
            "category": "Transport security",
            "severity": "Review",
            "status": "Review recommended",
            "evidence": f"Requested URL scheme: {urlparse(url).scheme}",
            "recommendation": "Use HTTPS for applications that handle sensitive information.",
            "limitation": "This check evaluates the supplied URL only and does not validate the site's full TLS configuration."
        })

    return {
        "tool": "Web Security Assessment Toolkit",
        "version": "1.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "server_header": response.headers.get("Server", "Not disclosed"),
        "content_type": response.headers.get("Content-Type", "Not disclosed"),
        "findings_count": len(findings),
        "findings": findings,
        "disclaimer": "Automated observations only. Findings require manual validation; absence of a finding does not establish security."
    }

def save_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def save_html(report: dict, path: Path) -> None:
    rows = []
    for f in report["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td>{html.escape(f['severity'])}</td>"
            f"<td>{html.escape(f['status'])}</td>"
            f"<td>{html.escape(f['evidence'])}</td>"
            f"<td>{html.escape(f['recommendation'])}</td>"
            "</tr>"
        )
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Assessment Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#202124}}
h1{{margin-bottom:.2rem}} .meta{{background:#f4f6f8;padding:1rem;border-radius:8px;overflow-wrap:anywhere}}
table{{width:100%;border-collapse:collapse;margin-top:1.2rem}} th,td{{border:1px solid #d9dee3;padding:.65rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#eef2f6}} .note{{background:#fff6dd;padding:1rem;border-left:4px solid #d99b00}}
</style></head><body>
<h1>Web Security Assessment Report</h1>
<p>Educational, non-intrusive assessment</p>
<div class="meta">
<p><b>Requested URL:</b> {html.escape(report['requested_url'])}</p>
<p><b>Final URL:</b> {html.escape(report['final_url'])}</p>
<p><b>HTTP status:</b> {report['http_status']}</p>
<p><b>Assessment time (UTC):</b> {html.escape(report['timestamp_utc'])}</p>
<p><b>Server header:</b> {html.escape(report['server_header'])}</p>
<p><b>Content type:</b> {html.escape(report['content_type'])}</p>
</div>
<table><thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Status</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="note"><b>Limitations:</b> {html.escape(report['disclaimer'])}
Automated checks can produce false positives and false negatives. Validate findings manually.</div>
</body></html>"""
    path.write_text(page, encoding="utf-8")

def main() -> int:
    parser = argparse.ArgumentParser(description="Non-intrusive web security header and cookie review.")
    parser.add_argument("url", help="Full URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
    args = parser.parse_args()

    try:
        url = validate_target(args.url)
        report = assess(url, timeout=args.timeout)
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = out_dir / f"assessment_{stamp}.json"
        html_path = out_dir / f"assessment_{stamp}.html"
        save_json(report, json_path)
        save_html(report, html_path)

        print("\nWEB SECURITY ASSESSMENT TOOLKIT")
        print("=" * 34)
        print(f"Final URL: {report['final_url']}")
        print(f"HTTP status: {report['http_status']}")
        print(f"Observations: {report['findings_count']}")
        for item in report["findings"]:
            print(f"[{item['severity'].upper()}] {item['title']}")
        print(f"\nJSON report: {json_path}")
        print(f"HTML report: {html_path}")
        print("\nReminder: review each observation manually before calling it a vulnerability.")
        return 0
    except (ValueError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
