#!/usr/bin/env python3
"""Normalize saved security-tool output files; this module never runs scanners."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 10_000
ALLOWED_TOOLS = {"nuclei", "zap", "httpx", "katana", "subfinder"}
SEVERITIES = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFORMATIONAL", "informational": "INFORMATIONAL",
    "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL",
}
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\\s*:\\s*(?:bearer|basic)\\s+)[^\\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret)\\s*[=:]\\s*)[\\\"']?[^\\s,;\\\"']+"),
    re.compile(r"(?i)((?:set-cookie|cookie)\\s*:\\s*)[^\\r\\n]+"),
    re.compile(r"(?i)((?:x-api-key|x-auth-token)\\s*:\\s*)[^\\r\\n]+"),
]
URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/@\\s:]+:[^/@\\s]+@")


def clean(value: Any, limit: int = 4000) -> str:
    """Convert untrusted values to bounded text and redact common credential forms."""
    sensitive = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
                 "api_key", "api-key", "access_token", "access-token", "refresh_token",
                 "refresh-token", "client_secret", "client-secret", "password", "passwd", "secret"}
    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            safe = {}
            for key, child in item.items():
                normalized = str(key).lower()
                if normalized in sensitive or any(word in normalized for word in ("password", "token", "secret", "cookie", "api_key", "api-key")):
                    safe[str(key)] = "[REDACTED]"
                else:
                    safe[str(key)] = redact(child)
            return safe
        if isinstance(item, list):
            return [redact(child) for child in item[:1000]]
        if not isinstance(item, str):
            return item
        text = item.replace("\\x00", "")
        text = URL_CREDENTIALS.sub(r"\\1[REDACTED]@", text)
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(r"\\1[REDACTED]", text)
        return text[:limit]
    result = redact(value)
    if isinstance(result, (dict, list)):
        result = json.dumps(result, ensure_ascii=False)
    return str(result or "")[:limit]

def severity(value: Any) -> str:
    return SEVERITIES.get(str(value or "info").strip().lower(), "INFORMATIONAL")


def normalize_record(tool: str, item: dict[str, Any]) -> dict[str, Any] | None:
    if tool not in ALLOWED_TOOLS or not isinstance(item, dict):
        return None
    if tool == "nuclei":
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        extracted = item.get("extracted-results")
        evidence = "; ".join(clean(x, 500) for x in extracted[:10]) if isinstance(extracted, list) else item.get("matcher-name")
        return {
            "source_tool": "Nuclei", "title": clean(info.get("name") or item.get("template-id") or "Nuclei observation", 300),
            "severity": severity(info.get("severity")),
            "asset": clean(item.get("matched-at") or item.get("host") or item.get("url"), 1000),
            "evidence": clean(evidence), "description": clean(info.get("description")),
            "remediation": clean(info.get("remediation")), "template_id": clean(item.get("template-id"), 200),
            "confidence": "Review source template and evidence",
        }
    if tool == "httpx":
        url = item.get("url") or item.get("input") or item.get("host")
        if not url:
            return None
        tech = item.get("tech") if isinstance(item.get("tech"), list) else []
        title = "HTTP service observed: " + clean(item.get("title") or item.get("webserver") or url, 200)
        facts = [f"status={clean(item.get('status_code', 'unknown'), 30)}",
                 f"webserver={clean(item.get('webserver'), 100)}"]
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
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
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
            if len(results) > MAX_RECORDS:
                raise ValueError("Input exceeds 10,000 records.")
    return results


def import_file(tool: str, source: Path) -> list[dict[str, Any]]:
    if tool not in ALLOWED_TOOLS:
        raise ValueError("Unsupported tool. Choose nuclei, zap, httpx, katana, or subfinder.")
    if not source.is_file():
        raise ValueError("Input file does not exist.")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Input file exceeds 10 MB.")
    raw = source.read_text(encoding="utf-8-sig")
    if tool == "zap":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("ZAP report is not valid JSON.") from exc
        if not isinstance(data, dict):
            raise ValueError("ZAP report must be a JSON object.")
        return parse_zap(data)
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), 1):
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
    return rows


def markdown_report(tool: str, rows: list[dict[str, Any]]) -> str:
    lines = [f"# NEXORA imported results — {clean(tool, 30)}", "",
             "> Imported from a local file. These observations are not independently verified. Discovery is not authorization.", "",
             f"- Records: {len(rows)}", ""]
    for index, row in enumerate(rows, 1):
        lines.extend([f"## {index}. {clean(row.get('title'), 300)}", "",
                      f"- Source: {clean(row.get('source_tool'), 50)}",
                      f"- Severity: {clean(row.get('severity'), 30)}",
                      f"- Asset: {clean(row.get('asset'), 1000)}", "",
                      "### Evidence", clean(row.get("evidence")) or "Not supplied",
                      "", "### Description", clean(row.get("description")) or "Not supplied",
                      "", "### Remediation", clean(row.get("remediation")) or "Review manually", ""])
    return "\n".join(lines) + "\n"
