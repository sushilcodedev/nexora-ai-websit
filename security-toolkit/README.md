# NEXORA Security Toolkit
Version 0.4.0 · Beginner-friendly toolkit · Free and local-first

A local-first toolkit for learning web security and organizing authorized bug-bounty work. It includes scope records, a low-impact HTTP header checker, Markdown reports, an open-source integration registry, a local Ollama AI security assistant, and a learner roadmap.

> Only assess systems you own or have explicit written permission to test. Program scope and rules override this toolkit. The header checker sends one HEAD request and does not follow redirects. The AI assistant analyzes text you supply; it does not scan or exploit targets.

## Features
- Scope Manager: authorized domains and exclusions.
- Header Checker: one HTTP HEAD request on a recorded in-scope URL.
- Report Builder: Markdown finding template with an in-scope asset gate.
- Open-source registry: Nuclei, httpx, Subfinder, Katana and OWASP ZAP. These are documented, not executed by this release.
- Local AI Security Assistant: analyze sanitized scan output using Ollama on this computer.
- Eight reusable AI-agent and learning skills in `skills/` and a dashboard Skills Library.
- Local scanner-result import adapters for Nuclei, OWASP ZAP, httpx, Katana and Subfinder JSON/JSONL exports. These adapters parse local files only; they do not install or run scanners.
- 30-day learner curriculum.
- No paid APIs or cloud AI services. Python standard library only.

## Quick start — Windows

Run these commands from the `security-toolkit` folder:

~~~powershell
py nexora_security.py init
py nexora_security.py integrations
py nexora_security.py doctor
py nexora_security.py import-results --tool nuclei --input path\\to\\nuclei.jsonl
py -m unittest discover -s tests -v
~~~

## Run the dashboard

~~~powershell
py -m http.server 8000
~~~

Open http://127.0.0.1:8000/dashboard/ . This is the static workspace; its AI Assistant page requires the local assistant server described below.

## Run the local AI Security Assistant

1. Install and start [Ollama](https://ollama.com/) on your computer.
2. Open PowerShell and download a model if you do not already have one:

~~~powershell
ollama pull deepseek-r1:8b
~~~

This model is several GB and may run slowly on CPU-only or 16 GB RAM computers. If it is already installed, do not download it again. Check with `ollama list`.

3. From the `security-toolkit` folder, start NEXORA:

~~~powershell
py ai_assistant.py
~~~

4. Open http://127.0.0.1:8765/ai-assistant.html

Keep the terminal and Ollama running while using it. The server binds only to `127.0.0.1`. It talks to Ollama at `127.0.0.1:11434`; pasted evidence is not sent to a remote AI provider.

The assistant accepts sanitized text evidence up to 30,000 characters. It provides a beginner-friendly explanation, estimated severity and confidence, safe lab verification ideas, remediation, and limitations. It does not run commands, fetch URLs, scan websites, or independently confirm a vulnerability. AI output may be incorrect and must be reviewed.

## Import existing scanner output (local files only)

NEXORA can normalize saved output from Nuclei, OWASP ZAP, httpx, Katana, and Subfinder into JSON and Markdown reports. It does not launch these tools or send targets anywhere.

~~~powershell
py nexora_security.py import-results --tool nuclei --input .\\nuclei-results.jsonl
py nexora_security.py import-results --tool zap --input .\\zap-report.json
py nexora_security.py import-results --tool httpx --input .\\httpx.jsonl
py nexora_security.py import-results --tool katana --input .\\katana.jsonl
py nexora_security.py import-results --tool subfinder --input .\\subdomains.txt
~~~

The importer redacts common token/cookie patterns, limits input files to 10 MB and records to 10,000, and labels discovery/metadata records as informational. Review all imported data; scanner output can contain false positives. Run upstream scanners separately only after reviewing their documentation, licence, current version, exact authorized scope, exclusions, rate limits and program rules. No automatic scanner execution is enabled.

## Skills library

Open the dashboard's **Skills Library** to browse eight Markdown skills:
- Agent skills: security triage, HTTP header review, report writing, scan-result explanation, secure code review.
- Learning skills: beginner cybersecurity tutor, legal lab coach, learning roadmap planner.

These are reusable instructions and educational material. They do not grant permission or execute actions.

## Linux/macOS

Use `python3` instead of `py` for the commands above. Install Ollama separately using its official instructions.

## Check an authorized asset

~~~bash
python nexora_security.py scope add --domain example.com --authorization "I own this domain / have written permission" --i-am-authorized
python nexora_security.py headers --url https://example.com
~~~

Replace example.com with an asset you own or have explicit written permission to test. The acknowledgement flag is a reminder, not legal proof.

## Privacy and safety
- Scope, findings and learning progress stay in your local workspace/browser.
- AI analysis is sent only to your local Ollama instance.
- Do not paste passwords, API keys, cookies, personal information, or customer secrets.
- Never commit secrets or customer data.
- A tool's open-source licence does not grant permission to test any system.

## Learning
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/

## Licence
Original NEXORA code and documentation are MIT-licensed. Third-party tools retain their own licences.
