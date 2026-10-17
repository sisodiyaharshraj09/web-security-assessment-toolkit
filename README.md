# Web Security Assessment Toolkit

A beginner-friendly Python project for an ethical-hacking portfolio. It performs a **single HTTP GET request** and reviews selected HTTP security headers, response metadata, and visible cookie attributes. It exports HTML and JSON reports.

## Safety and scope

- Use only on `localhost`, systems you own, or targets you have explicit permission to assess.
- For non-local hosts, the program asks you to confirm authorization.
- The tool does not crawl, exploit, brute-force, submit forms, or test login bypasses.
- Automated observations are not proof of a vulnerability. Validate results manually.
- Do not publish credentials, session tokens, personal data, or unredacted screenshots.

## Features

- Security-header presence review:
  - Content-Security-Policy
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Strict-Transport-Security
- Best-effort review of `Secure`, `HttpOnly`, and `SameSite` cookie attributes.
- Notes whether the supplied URL uses HTTP or HTTPS.
- HTML and JSON report output.
- Clear limitations and remediation guidance.

## Requirements

- Python 3.10+
- `pip`
- Network access only to the authorized test target

## Setup on Kali Linux / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv
cd web_security_assessment_toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run a safe local test

```bash
python scanner.py http://127.0.0.1:8000
```

If you need a quick local HTTP server for a harmless test page, create `test-page/index.html` and run:

```bash
mkdir -p test-page
printf '<!doctype html><title>Local test</title><h1>Security toolkit test page</h1>' > test-page/index.html
python3 -m http.server 8000 --directory test-page
```

Open a second terminal, activate the virtual environment, and run the scanner command above. The Python static server may not send the headers this toolkit checks; that is expected.

For an authorized HTTPS test, provide the full HTTPS URL. Never disable TLS certificate verification to silence errors.

## Output

Reports are saved in the `reports/` directory:
- `assessment_YYYYMMDD_HHMMSS.json`
- `assessment_YYYYMMDD_HHMMSS.html`

You can specify a different output directory:

```bash
python scanner.py http://127.0.0.1:8000 --out reports/demo
```

## Suggested portfolio improvements

1. Add unit tests for the report formatting functions.
2. Add a configurable header policy file.
3. Add a CSV export.
4. Add a small dashboard that displays previous local reports.
5. Add screenshots of a local test run and an example report, with no sensitive data.
6. Write a short reflection explaining false positives, false negatives, and why missing headers alone do not prove exploitability.

## Resume bullet (use only after you have run and understood it)

**Web Security Assessment Toolkit — Python, Requests, HTTP**
- Built a non-intrusive Python utility to review selected HTTP security headers and cookie attributes.
- Generated timestamped HTML and JSON reports with evidence, recommendations, and limitations.
- Documented safe testing scope and manual validation requirements.

## Learning references

- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/

## Disclaimer

This is an educational starter project, not a replacement for a professional penetration test or a comprehensive vulnerability scanner.
