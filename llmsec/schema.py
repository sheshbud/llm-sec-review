"""Schema for a security finding, plus validation of model output.

The reviewer asks Claude for JSON. Model output is untrusted: it can be malformed,
it can invent fields, and on the adversarial samples it may be actively steered by
instructions embedded in the code under review. Everything crossing that boundary
goes through validate_findings() before it is counted.
"""
import re

SEVERITIES = ("low", "medium", "high", "critical")
CWE_RE = re.compile(r"^CWE-\d{1,4}$")
MAX_FINDINGS = 100


class SchemaError(ValueError):
    pass


def validate_findings(payload, max_line):
    """Coerce raw model output into a list of findings, or raise SchemaError.

    Returns a list of {line, cwe, severity, name, description}. Rejects anything
    that is not shaped like a findings list; silently drops individual findings
    that are malformed, so one bad entry cannot discard a whole report.
    """
    if not isinstance(payload, dict):
        raise SchemaError("top level is %s, expected object" % type(payload).__name__)
    items = payload.get("findings")
    if not isinstance(items, list):
        raise SchemaError("'findings' is %s, expected list" % type(items).__name__)
    if len(items) > MAX_FINDINGS:
        raise SchemaError("%d findings exceeds cap of %d" % (len(items), MAX_FINDINGS))

    out, dropped = [], 0
    for it in items:
        if not isinstance(it, dict):
            dropped += 1
            continue
        try:
            line = int(it.get("line"))
        except (TypeError, ValueError):
            dropped += 1
            continue
        if not 1 <= line <= max_line:
            dropped += 1
            continue
        cwe = str(it.get("cwe", "")).strip().upper()
        if not CWE_RE.match(cwe):
            dropped += 1
            continue
        sev = str(it.get("severity", "")).strip().lower()
        if sev not in SEVERITIES:
            sev = "medium"
        out.append({
            "line": line,
            "cwe": cwe,
            "severity": sev,
            "name": str(it.get("name", ""))[:80],
            "description": str(it.get("description", ""))[:400],
        })
    return out, dropped
