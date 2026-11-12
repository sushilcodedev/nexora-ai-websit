# Integration roadmap
## Phase 1 — Registry (current)
- Maintain registry of tools, licences, repository URLs, executable names, and status.
- Detect executable availability only; do not invoke tools.
- Keep tools separately installed by the user.
## Phase 2 — Adapter interfaces
- Define preflight, version, scope validation, command builder, execute, stop, and output parser.
- Add dry-run mode that prints sanitized commands without executing.
- Require explicit authorization confirmation before process execution.
## Phase 3 — Controlled workflows
- Begin with passive discovery and manually selected assets.
- Require per-run scope, exclusions, rate limits, and timeouts.
- Never run broad scans by default.
- Do not enable exploit, brute-force, denial-of-service, credential, or destructive modes.
## Phase 4 — Results and evidence
- Normalize output into a common finding format.
- Preserve evidence and tool/version provenance.
- Mark unverified observations as leads, not confirmed vulnerabilities.
- Redact secrets and personal information before saving or exporting.
## Release gate
No scanner adapter should be enabled until tests prove out-of-scope hosts and excluded subdomains are rejected, dry-run starts no process, and active execution requires explicit user approval.
