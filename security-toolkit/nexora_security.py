#!/usr/bin/env python3
"""NEXORA Security Toolkit: safe, local-first bug-bounty workflow helpers.

The MVP only performs one HTTP HEAD request for the header check. It does not
crawl, fuzz, exploit, brute-force, follow redirects, or run third-party scanners.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

APP_NAME = "NEXORA Security Toolkit"
VERSION = "0.4.0"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / ".nexora"
SCOPE_FILE = DATA_DIR / "scope.json"
REPORT_DIR = ROOT / "reports"
INTEGRATIONS_FILE = ROOT / "integrations.json"
USER_AGENT = "NEXORA-Security-Toolkit/0.4.0 (low-impact-header-checker)"


class ScopeError(ValueError):
    """Raised when an asset is not in the recorded authorized scope."""


def normalize_host(value: str) -> str:
    """Normalize a hostname/domain; reject URLs, paths, wildcards and bad names."""
    raw = value.strip().lower().rstrip(".")
    if not raw or "://" in raw or "/" in raw or "*" in raw or "@" in raw:
        raise ValueError("Enter a hostname only, e.g. example.com (no URL, path, or wildcard).")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        try:
            host = raw.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid internationalized hostname.") from exc
        if len(host) > 253 or not all(
            part and len(part) <= 63 and part[0] != "-" and part[-1] != "-"
            and all(ch.isalnum() or ch == "-" for ch in part)
            for part in host.split(".")
        ):
            raise ValueError("Invalid hostname.")
        return host


def load_scope(path: Path = SCOPE_FILE) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "authorized": [], "excluded": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read scope file: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Scope file must contain a JSON object.")
    data.setdefault("authorized", [])
    data.setdefault("excluded", [])
    return data


def save_scope(data: dict[str, Any], path: Path = SCOPE_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def host_matches(host: str, entry: str) -> bool:
    """Match exact host or a true subdomain; never substring-match."""
    return host == entry or host.endswith("." + entry)


def is_in_scope(host: str, scope: dict[str, Any]) -> bool:
    host = normalize_host(host)
    authorized = [normalize_host(x["domain"]) for x in scope.get("authorized", [])]
    excluded = [normalize_host(x) for x in scope.get("excluded", [])]
    return any(host_matches(host, item) for item in authorized) and not any(
        host_matches(host, item) for item in excluded
    )


def validate_url(url: str, scope: dict[str, Any]) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL must have a hostname and must not contain embedded credentials.")
    host = normalize_host(parsed.hostname)
    if not is_in_scope(host, scope):
        raise ScopeError(f"{host} is not in your authorized scope, or is explicitly excluded.")
    return parsed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects; a redirect can leave the authorized scope."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_headers(url: str, scope: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    parsed = validate_url(url, scope)
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    try:
        status = getattr(response, "code", None)
        headers = {k.lower(): v for k, v in response.headers.items()}
    finally:
        response.close()

    checks = []
    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"header": name, "present": ok, "detail": detail})

    csp = headers.get("content-security-policy")
    add("Content-Security-Policy", bool(csp), "Present" if csp else "Missing; assess a policy appropriate to the application.")
    hsts = headers.get("strict-transport-security")
    if parsed.scheme == "https":
        add("Strict-Transport-Security", bool(hsts), "Present" if hsts else "Missing on HTTPS; assess HSTS suitability.")
    else:
        add("Strict-Transport-Security", bool(hsts), "Not evaluated as a positive control on plain HTTP.")
    xcto = headers.get("x-content-type-options", "")
    add("X-Content-Type-Options", xcto.lower() == "nosniff", "nosniff set" if xcto.lower() == "nosniff" else "Missing or not set to nosniff.")
    referrer = headers.get("referrer-policy")
    add("Referrer-Policy", bool(referrer), "Present" if referrer else "Missing; choose a policy matching privacy needs.")
    permissions = headers.get("permissions-policy")
    add("Permissions-Policy", bool(permissions), "Present" if permissions else "Missing; restrict browser features where appropriate.")
    xfo = headers.get("x-frame-options")
    csp_frame = bool(csp and "frame-ancestors" in csp.lower())
    add("Clickjacking protection", bool(xfo) or csp_frame, "X-Frame-Options or CSP frame-ancestors present" if (xfo or csp_frame) else "Neither X-Frame-Options nor CSP frame-ancestors detected.")
    return {
        "url": url,
        "host": parsed.hostname,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "http_status": status,
        "checks": checks,
        "note": "A missing header is a review item, not proof of an exploitable vulnerability. HEAD responses may differ from GET responses.",
    }


def write_report(args: argparse.Namespace, scope: dict[str, Any]) -> Path:
    parsed = validate_url(args.asset, scope)
    severity = args.severity.upper()
    allowed = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if severity not in allowed:
        raise ValueError("Invalid severity.")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    safe_title = "".join(ch.lower() if ch.isalnum() else "-" for ch in args.title).strip("-")
    safe_title = "-".join(filter(None, safe_title.split("-")))[:60] or "finding"
    output = Path(args.output) if args.output else REPORT_DIR / f"{timestamp}-{safe_title}.md"
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    body = f"""# {args.title}

- **Severity:** {severity}
- **Asset:** {args.asset}
- **Host:** {parsed.hostname}
- **Created (UTC):** {dt.datetime.now(dt.timezone.utc).isoformat()}
- **Program / authorization reference:** {args.authorization_reference or "Not supplied"}

## Summary

{args.description}

## Impact

{args.impact}

## Steps to reproduce

{args.steps}

## Evidence

{args.evidence or "No evidence supplied. Add only minimal, redacted evidence from an authorized test."}

## Recommended remediation

{args.remediation}

## Scope and disclosure

This report was prepared for an asset recorded in the local NEXORA scope file. Re-check the live program scope, testing rules, and disclosure process before submitting. Remove secrets, personal data, and unrelated user information.
"""
    output.write_text(body, encoding="utf-8")
    return output


def cmd_init(_: argparse.Namespace) -> int:
    if not SCOPE_FILE.exists():
        save_scope({"version": 1, "authorized": [], "excluded": []})
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Initialized local workspace: {DATA_DIR}")
    print("No network requests were made.")
    return 0


def cmd_scope_add(args: argparse.Namespace) -> int:
    if not args.i_am_authorized:
        raise ValueError("Add --i-am-authorized only after confirming ownership or written permission.")
    domain = normalize_host(args.domain)
    data = load_scope()
    if any(x.get("domain") == domain for x in data["authorized"]):
        print(f"Already recorded: {domain}")
        return 0
    data["authorized"].append({
        "domain": domain,
        "authorization": args.authorization.strip(),
        "added_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    save_scope(data)
    print(f"Added authorized domain: {domain}")
    print("Local registration does not replace written authorization or program scope.")
    return 0


def cmd_scope_exclude(args: argparse.Namespace) -> int:
    domain = normalize_host(args.domain)
    data = load_scope()
    if domain not in data["excluded"]:
        data["excluded"].append(domain)
    save_scope(data)
    print(f"Excluded: {domain} (including its subdomains)")
    return 0


def cmd_scope_list(_: argparse.Namespace) -> int:
    data = load_scope()
    print("AUTHORIZED")
    for item in data["authorized"]:
        print(f"  - {item['domain']} | {item.get('authorization', 'No note')}")
    print("EXCLUDED")
    for item in data["excluded"]:
        print(f"  - {item}")
    if not data["authorized"]:
        print("  (none yet — add only assets you are authorized to test)")
    return 0


def cmd_headers(args: argparse.Namespace) -> int:
    result = check_headers(args.url, load_scope())
    print(f"Target: {result['url']}")
    print(f"HTTP status: {result['http_status']}")
    for item in result["checks"]:
        state = "OK" if item["present"] else "REVIEW"
        print(f"[{state}] {item['header']}: {item['detail']}")
    print(result["note"])
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"JSON saved: {args.json}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    output = write_report(args, load_scope())
    print(f"Report created: {output}")
    print("Review and redact it before sharing. No report was uploaded.")
    return 0


def load_integrations() -> list[dict[str, Any]]:
    try:
        data = json.loads(INTEGRATIONS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read integration registry: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("Integration registry must be a JSON array.")
    return data


def cmd_integrations(_: argparse.Namespace) -> int:
    print(f"{APP_NAME} {VERSION} — open-source integration registry")
    for item in load_integrations():
        print(f"\n{item['name']} [{item['license']}]")
        print(f"  Purpose: {item['purpose']}")
        print(f"  Binary: {item['binary']}")
        print(f"  Status: {item['status']}")
        print(f"  Source: {item['repository']}")
    print("\nRegistry only: NEXORA does not install or execute these tools.")
    print("Confirm written authorization, scope, exclusions, and program rules before active testing.")
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"{APP_NAME} {VERSION}")
    print(f"Python: {sys.version.split()[0]} ({'OK' if sys.version_info >= (3, 10) else 'upgrade required'})")
    for item in load_integrations():
        binary = item['binary']
        print(f"{item['name']} ({binary}): {shutil.which(binary) or 'not installed (optional)'}")
    print("Detection only: no scanners were started and no network requests were made.")
    return 0

def cmd_import_results(args: argparse.Namespace) -> int:
    from integrations import import_file, markdown_report
    source = Path(args.input)
    rows = import_file(args.tool, source)
    output = Path(args.output)
    markdown = Path(args.markdown)
    if not output.is_absolute():
        output = ROOT / output
    if not markdown.is_absolute():
        markdown = ROOT / markdown
    output.parent.mkdir(parents=True, exist_ok=True)
    markdown.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"tool": args.tool, "count": len(rows), "findings": rows}, indent=2) + "\\n", encoding="utf-8")
    markdown.write_text(markdown_report(args.tool, rows), encoding="utf-8")
    print(f"Imported {len(rows)} local record(s).")
    print(f"JSON: {output}")
    print(f"Markdown: {markdown}")
    print("No scanner was executed and no network request was made.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="initialize local workspace")
    init.set_defaults(func=cmd_init)

    scope = sub.add_parser("scope", help="manage authorized assets")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    add = scope_sub.add_parser("add", help="add an explicitly authorized domain")
    add.add_argument("--domain", required=True)
    add.add_argument("--authorization", required=True, help="brief ownership/permission note; no secrets")
    add.add_argument("--i-am-authorized", action="store_true", help="confirm ownership or written permission")
    add.set_defaults(func=cmd_scope_add)
    exclude = scope_sub.add_parser("exclude", help="exclude a host/domain and its subdomains")
    exclude.add_argument("--domain", required=True)
    exclude.set_defaults(func=cmd_scope_exclude)
    listing = scope_sub.add_parser("list", help="show local scope")
    listing.set_defaults(func=cmd_scope_list)

    headers = sub.add_parser("headers", help="check headers with one in-scope HEAD request")
    headers.add_argument("--url", required=True)
    headers.add_argument("--json", help="optional JSON output path")
    headers.set_defaults(func=cmd_headers)

    report = sub.add_parser("report", help="create a Markdown finding for an in-scope asset")
    report.add_argument("--title", required=True)
    report.add_argument("--asset", required=True)
    report.add_argument("--severity", default="INFORMATIONAL")
    report.add_argument("--description", required=True)
    report.add_argument("--impact", required=True)
    report.add_argument("--steps", required=True)
    report.add_argument("--remediation", required=True)
    report.add_argument("--evidence", default="")
    report.add_argument("--authorization-reference", default="")
    report.add_argument("--output")
    report.set_defaults(func=cmd_report)

    integrations = sub.add_parser("integrations", help="list documented open-source integrations")
    integrations.set_defaults(func=cmd_integrations)

    imported = sub.add_parser("import-results", help="normalize a local scanner output file; does not run scanners")
    imported.add_argument("--tool", choices=["nuclei", "zap", "httpx", "katana", "subfinder"], required=True)
    imported.add_argument("--input", required=True, help="local JSONL or JSON report file")
    imported.add_argument("--output", default="reports/imported-findings.json")
    imported.add_argument("--markdown", default="reports/imported-findings.md")
    imported.set_defaults(func=cmd_import_results)

    doctor = sub.add_parser("doctor", help="check local prerequisites and optional tool paths")
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, ScopeError, OSError, urllib.error.URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
