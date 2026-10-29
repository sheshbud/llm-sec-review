"""Semgrep baseline: run the registry Python rules and normalize to the same
finding shape the LLM reviewer produces, so the two are directly comparable.
"""
import json
import re
import subprocess

CWE_RE = re.compile(r"(CWE-\d{1,4})")
CONFIGS = ("p/python", "p/security-audit")


def run(sample_dir, configs=CONFIGS, timeout=600):
    """Run Semgrep over sample_dir. Returns {filename: [findings]}."""
    cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(str(sample_dir))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if not proc.stdout.strip():
        raise RuntimeError("semgrep produced no output: %s" % proc.stderr[-400:])

    out = {}
    for r in json.loads(proc.stdout).get("results", []):
        name = r["path"].rsplit("/", 1)[-1]
        meta = r["extra"].get("metadata", {})
        blob = json.dumps(meta)
        m = CWE_RE.search(blob)
        out.setdefault(name, []).append({
            "line": r["start"]["line"],
            "cwe": m.group(1) if m else "CWE-0",
            "severity": r["extra"].get("severity", "WARNING").lower(),
            "name": r["check_id"].rsplit(".", 1)[-1],
            "description": r["extra"].get("message", "").strip()[:400],
        })
    return out
