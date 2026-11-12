# Architecture

## Design goals
- Local-first and free to run.
- Python standard library only.
- No account, telemetry, analytics, cloud API, or remote storage.
- Explicit scope gate before network access.
- Low-impact behavior by default.

## Current data flow
1. User records an authorized domain in .nexora/scope.json.
2. headers parses the URL and checks exact-domain / subdomain boundaries.
3. Exclusions override authorization.
4. The tool sends one HTTP HEAD request, does not follow redirects, and closes the response.
5. Results are printed locally; optional JSON output is written to a user-selected path.
6. report checks that the finding asset is in scope before writing Markdown locally.

## Known limitations
- Scope records are user assertions, not cryptographic proof of authorization.
- A HEAD response may differ from a GET response.
- Header presence is not a security guarantee; policy quality and application behavior matter.
- The checker does not crawl, authenticate, fuzz, test business logic, or confirm exploitability.
- No automatic scanner integration is enabled in this MVP.
