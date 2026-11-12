# Open-source integrations and license policy

NEXORA currently does not copy or bundle third-party scanner source code. It can coexist with independently installed tools.

| Project | Upstream | License noted by upstream | Current integration |
|---|---|---|---|
| Nuclei | https://github.com/projectdiscovery/nuclei | MIT | Optional installation detected by doctor; not executed |
| ProjectDiscovery httpx | https://github.com/projectdiscovery/httpx | MIT | Optional installation detected by doctor; not executed |
| OWASP ZAP | https://github.com/zaproxy/zaproxy | Apache-2.0 | Optional installation detected by doctor; not executed |

## Reuse checklist
Before copying, modifying, bundling, or redistributing third-party code, templates, rules, or assets:
1. Inspect the exact repository and version's LICENSE file.
2. Check all bundled dependencies and template repositories separately.
3. Preserve copyright, attribution, and license notices as required.
4. Include required NOTICE / attribution files for licenses that require them.
5. Record upstream URL, version or commit, changes, and license.
6. Do not assume a public repository or a scanner's MIT license makes every external template or dataset MIT-licensed.
7. Re-check the license before shipping a release.

NEXORA's own code in this folder is MIT-licensed. Third-party software retains its own license and is not relicensed by NEXORA.
