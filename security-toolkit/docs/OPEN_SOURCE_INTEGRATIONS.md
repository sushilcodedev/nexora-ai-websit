# Open-source integrations
NEXORA uses an adapter-first approach: upstream tools remain separate executables and retain their own licences. This repository does not copy their source code, templates, rules, or binaries.
| Tool | Licence | Role | NEXORA status |
|---|---|---|---|
| Nuclei | MIT | Template-based vulnerability checks; active scanning requires policy and scope review. | Registry and local binary detection only |
| ProjectDiscovery httpx | MIT | HTTP service probing and metadata collection. | Registry and local binary detection only |
| Subfinder | MIT | Passive subdomain discovery; review data-source terms. | Registry and local binary detection only |
| Katana | MIT | Web crawling; request volume must be controlled. | Registry and local binary detection only |
| OWASP ZAP | Apache-2.0 | Web application security proxy and scanner. | Registry and local binary detection only |
## Official repositories
- [Nuclei](https://github.com/projectdiscovery/nuclei) — MIT
- [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) — MIT
- [Subfinder](https://github.com/projectdiscovery/subfinder) — MIT
- [Katana](https://github.com/projectdiscovery/katana) — MIT
- [OWASP ZAP](https://github.com/zaproxy/zaproxy) — Apache-2.0
## Commands
~~~bash
python nexora_security.py integrations
python nexora_security.py doctor
~~~
These commands list projects and detect local executable names. They do not install or run scanners.
## Safety requirements
1. Confirm ownership or explicit written authorization for each exact asset.
2. Re-read live program scope, exclusions, allowed techniques, rate limits, and safe-harbor terms.
3. Explain the selected tool, expected requests, and potential impact.
4. Require explicit user confirmation for each active run.
5. Enforce exact host scope and exclusions before launching a process.
6. Apply conservative rate/concurrency defaults, bounded timeouts, and a stop control.
7. Capture tool version, options, timestamp, and authorization reference.
8. Sanitize output; keep tokens, cookies, personal data, and secrets out of logs and Git.
9. Treat third-party templates, data sources, and dependencies as separately licensed components.
## Licence verification
Licences were read from upstream GitHub repository metadata during this update. Verify exact release LICENSE and dependencies before packaging. A project's licence does not automatically cover templates, data sources, plugins, or dependencies.
