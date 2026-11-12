# NEXORA Security Toolkit

Version 0.1.0 · Beginner-friendly MVP · Free and local-first

A local-first toolkit for learning web security and organizing authorized bug-bounty work. It includes an explicit authorization scope register, a low-impact HTTP security-header checker, Markdown report generation, AI-agent operating skills, and a learner roadmap.

> Safety: Only assess systems you own or have explicit written permission to test. Program scope and rules always override this toolkit. The header checker sends one HEAD request and does not follow redirects. It is not a penetration tester and cannot prove a site is secure.

## Features
- Scope Manager: record authorized domains and exclusions in .nexora/scope.json.
- Header Checker: inspect common defensive HTTP response headers on an in-scope URL.
- Report Builder: generate a structured Markdown finding after checking that its asset is in scope.
- AI-agent skills: scope validation, safe planning, evidence handling, and reporting.
- Learner skills: 30-day beginner curriculum and lab-notes template.
- No paid APIs or cloud services. Python standard library only.

## Requirements
- Python 3.10 or newer
- Windows, macOS, or Linux
- No pip packages required

## Quick start

Windows PowerShell:
~~~powershell
py --version
py nexora_security.py init
py nexora_security.py scope add --domain example.com --authorization "I own this domain / have written permission" --i-am-authorized
py nexora_security.py scope list
py nexora_security.py headers --url https://example.com
~~~

Kali Linux / macOS / Linux:
~~~bash
python3 --version
python3 nexora_security.py init
python3 nexora_security.py scope add --domain example.com --authorization "I own this domain / have written permission" --i-am-authorized
python3 nexora_security.py scope list
python3 nexora_security.py headers --url https://example.com
~~~

Replace example.com with a domain you own or are explicitly authorized to test. The authorization flag is a reminder, not legal proof. Keep the program's written scope and rules.

## Commands
| Command | Purpose |
|---|---|
| init | Create local configuration |
| scope add | Add an authorized domain (requires acknowledgement) |
| scope exclude | Add an excluded host/domain |
| scope list | Display current scope |
| headers --url URL | Make one in-scope HEAD request and review headers |
| report | Create a Markdown report for an in-scope asset |
| doctor | Check Python and optional scanner availability |

Run python nexora_security.py --help for full help.

## Data and privacy
Scope and report files are saved locally. The tool does not upload targets, findings, cookies, credentials, or scan output. Do not put secrets, session tokens, private customer data, or credentials into reports or Git commits. .nexora/ and generated reports are ignored by Git.

## Open-source integrations
No third-party scanner source code is bundled. Optional external tools can be installed separately:
- Nuclei: https://github.com/projectdiscovery/nuclei (MIT)
- ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx (MIT)
- OWASP ZAP: https://github.com/zaproxy/zaproxy (Apache-2.0)

This MVP does not automatically execute any of these tools. Their presence is only reported by the doctor command. Review exact versions, dependencies, templates, and licenses before reuse.

## Learning
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/

Follow skills/learner/30-day-roadmap.md.

## Tests
~~~bash
python -m unittest discover -s tests -v
~~~

## License
Original NEXORA code and documentation in this directory are licensed under the MIT License in LICENSE. Third-party tools retain their own licenses. This license does not grant permission to test any system.
