# NEXORA Security Toolkit
Version 0.2.0 · Beginner-friendly MVP · Free and local-first
A local-first toolkit for learning web security and organizing authorized bug-bounty work. It includes scope records, a low-impact HTTP header checker, Markdown reports, an open-source integration registry, AI-agent skills, and a learner roadmap.
> Only assess systems you own or have explicit written permission to test. Program scope and rules override this toolkit. The header checker sends one HEAD request and does not follow redirects. It is not a penetration tester.
## Features
- Scope Manager: authorized domains and exclusions.
- Header Checker: one HTTP HEAD request on a recorded in-scope URL.
- Report Builder: Markdown finding template with an in-scope asset gate.
- Open-source registry: Nuclei, httpx, Subfinder, Katana and OWASP ZAP.
- AI-agent safety skill and 30-day learner curriculum.
- No paid APIs or cloud services. Python standard library only.
## Quick start — Windows
~~~powershell
py nexora_security.py init
py nexora_security.py integrations
py nexora_security.py doctor
py -m unittest discover -s tests -v
~~~
## Quick start — Linux/macOS
~~~bash
python3 nexora_security.py init
python3 nexora_security.py integrations
python3 nexora_security.py doctor
python3 -m unittest discover -s tests -v
~~~
## Check an authorized asset
~~~bash
python nexora_security.py scope add --domain example.com --authorization "I own this domain / have written permission" --i-am-authorized
python nexora_security.py headers --url https://example.com
~~~
Replace example.com with an authorized domain. The acknowledgement flag is a reminder, not legal proof.
## Local dashboard

The dashboard is a static, local-first browser interface. It stores scope records, findings, learning progress, and export counts in your browser's localStorage. It does not transmit this data to a server. Do not use a shared/public computer for sensitive notes.

Start a local server from the security-toolkit directory:

~~~powershell
py -m http.server 8000
~~~

Then open http://127.0.0.1:8000/dashboard/ in your browser. Keep the terminal window open while using the dashboard. On Linux/macOS use `python3 -m http.server 8000`.

Dashboard features:
- Overview and recent local activity
- Authorized asset records and exclusions
- Open-source integration registry
- Manual finding register with severity and status
- Markdown report and JSON backup import/export
- Beginner learning checklist

The dashboard does not launch scanners or verify authorization. Use the Python CLI for the existing low-impact, scope-gated header check.

## Open-source integrations
See docs/OPEN_SOURCE_INTEGRATIONS.md and docs/INTEGRATION_ROADMAP.md. The registry and doctor commands only list projects and detect local executable names. NEXORA does not install or execute third-party scanners in this release.
## Learning
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
## Privacy
Scope and reports are local. NEXORA does not upload findings, cookies, credentials, or scan output. Never commit secrets or customer data.
## Licence
Original NEXORA code and documentation are MIT-licensed. Third-party tools retain their own licences. A licence does not grant permission to test any system.
