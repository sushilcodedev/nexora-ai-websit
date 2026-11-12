#!/usr/bin/env python3
"""Normalize local result files from common security tools; never runs scanners."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 10_000
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"),
]
SEVERITIES = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
              "low": "LOW", "info": "INFORMATIONAL", "informational": "INFORMATIONAL",
              "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}


def clean(value: Any, limit: int = 4000) -> str:
    text = str(value or "")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text[:limit]


def severity(value: Any) -> str:
    return SEVERITIES.get(str(value or "info").strip().lower(), "INFORMATIONAL")


def normalize_record(tool: str, item: dict[str, Any]) -> dict[str, Any] | None:
    if tool == "nuclei":
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        name = info.get("name") or item.get("template-id") or "Nuclei observation"
        return {
            "source_tool": "Nuclei", "title": clean(name, 300),
            "severity": severity(info.get("severity")),
            "asset": clean(item.get("matched-at") or item.get("host") or item.get("url"), 1000),
            "evidence": clean("; ".join(map(str, item.get("extracted-results", [])[:10])) if isinstance(item.get("extracted-results"), list) else item.get("matcher-name")),
            "description": clean(info.get("description")), "remediation": clean(info.get("remediation")),
            "template_id": clean(item.get("template-id"), 200), "confidence": "Review source template and evidence",
        }
    if tool == "httpx":
        url = item.get("url") or item.get("input") or item.get("host")
        if not url:
            return None
        tech = item.get("tech") if isinstance(item.get("tech"), list) else []
        title = "HTTP service observed: " + clean(item.get("title") or item.get("webserver") or url, 200)
        facts = [f"status={item.get('status_code', 'unknown')}", f"webserver={clean(item.get('webserver'), 100)}"]
        facts.extend("technology=" + clean(x, 100) for x in tech[:10])
        return {"source_tool": "httpx", "title": title, "severity": "INFORMATIONAL",
                "asset": clean(url, 1000), "evidence": "; ".join(facts),
                "description": "Service metadata observation only; not a vulnerability by itself.",
                "remediation": "No remediation implied. Review whether exposed metadata is necessary."}
    if tool == "katana":
        url = item.get("url")
        if not url:
            return None
        return {"source_tool": "Katana", "title": "Discovered URL",
                "severity": "INFORMATIONAL", "asset": clean(url, 1000),
                "evidence": clean(item.get("source") or item.get("tag") or "URL discovered by crawler"),
                "description": "Discovered URL only; this record does not establish a vulnerability.",
                "remediation": "Review whether the route should be publicly reachable."}
    if tool == "subfinder":
        host = item.get("host") or item.get("input") or item.get("domain")
        if not host:
            return None
        return {"source_tool": "Subfinder", "title": "Discovered hostname",
                "severity": "INFORMATIONAL", "asset": clean(host, 1000),
                "evidence": "Hostname returned by passive subdomain discovery.",
                "description": "Asset discovery observation only; not a vulnerability or authorization.",
                "remediation": "Verify ownership and explicit scope before any testing."}
    return None


def parse_zap(data: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    sites = data.get("site", [])
    if not isinstance(sites, list):
        return results
    for site in sites:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []) if isinstance(site.get("alerts", []), list) else []:
            if not isinstance(alert, dict):
                continue
            risk = alert.get("riskcode", alert.get("risk", "0"))
            results.append({
                "source_tool": "OWASP ZAP", "title": clean(alert.get("alert") or alert.get("name") or "ZAP alert", 300),
                "severity": severity(risk), "asset": clean(alert.get("url") or site.get("@name"), 1000),
                "evidence": clean(alert.get("evidence") or alert.get("param")),
                "description": clean(alert.get("desc") or alert.get("description")),
                "remediation": clean(alert.get("solution")), "confidence": clean(alert.get("confidence"), 100),
                "reference": clean(alert.get("reference"), 1000),
            })
    return results


def import_file(tool: str, source: Path) -> list[dict[str, Any]]:
    if not source.is_file():
        raise ValueError("Input file does not exist.")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Input file exceeds 10 MB.")
    if tool == "zap":
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("ZAP report must be a JSON object.")
        rows = parse_zap(data)
    else:
        rows = []
        for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            if len(rows) >= MAX_RECORDS:
                raise ValueError("Input exceeds 10,000 records.")
            if tool == "subfinder":
                item = {"host": line.strip()}
            else:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {line_no}.") from exc
            if not isinstance(item, dict):
                continue
            normalized = normalize_record(tool, item)
            if normalized:
                rows.append(normalized)
    if len(rows) > MAX_RECORDS:
        raise ValueError("Input exceeds 10,000 records.")
    return rows


def markdown_report(tool: str, rows: list[dict[str, Any]]) -> str:
    lines = [f"# NEXORA imported results — {tool}", "",
             "> Imported from a local file. These observations are not independently verified. Discovery is not authorization.", "",
             f"- Records: {len(rows)}", ""]
    for index, row in enumerate(rows, 1):
        lines.extend([f"## {index}. {row['title']}", "",
                      f"- Source: {row['source_tool']}", f"- Severity: {row['severity']}",
                      f"- Asset: {row['asset']}", "", "### Evidence", row.get("evidence") or "Not supplied",
                      "", "### Description", row.get("description") or "Not supplied",
                      "", "### Remediation", row.get("remediation") or "Review manually", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import local scanner output into NEXORA normalized findings.")
    parser.add_argument("--tool", choices=["nuclei", "zap", "httpx", "katana", "subfinder"], required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/imported-findings.json"))
    parser.add_argument("--markdown", type=Path, default=Path("reports/imported-findings.md"))
    args = parser.parse_args()
    try:
        rows = import_file(args.tool, args.input)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"tool": args.tool, "count": len(rows), "findings": rows}, indent=2) + "\n", encoding="utf-8")
        args.markdown.write_text(markdown_report(args.tool, rows), encoding="utf-8")
        print(f"Imported {len(rows)} record(s).")
        print(f"JSON: {args.output}")
        print(f"Markdown: {args.markdown}")
        print("No scanner was executed and no network request was made.")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
