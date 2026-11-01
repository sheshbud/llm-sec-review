"""Normalize and dedupe findings. Model output is untrusted, so every field is checked."""
from __future__ import annotations

import re

SEVERITIES = ("low", "medium", "high", "critical")
CWE_RE = re.compile(r"^CWE-\d{1,4}$")


def normalize(raw, n_lines: int) -> dict | None:
    if not isinstance(raw, dict):
        return None
    try:
        line = int(raw.get("line"))
    except (TypeError, ValueError):
        return None
    cwe = str(raw.get("cwe", "")).strip().upper().replace("CWE ", "CWE-")
    sev = str(raw.get("severity", "")).strip().lower()
    if not (1 <= line <= n_lines) or not CWE_RE.match(cwe) or sev not in SEVERITIES:
        return None
    return {
        "line": line,
        "cwe": cwe,
        "severity": sev,
        "title": str(raw.get("title", ""))[:120],
        "rationale": str(raw.get("rationale", ""))[:600],
    }


def dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: (f["line"], f["cwe"])):
        key = (f["line"], f["cwe"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
