"""Knowledge base loaders.

Structured source: MITRE's CWE catalog XML (download cwec_latest.xml.zip from
cwe.mitre.org). Parsed namespace-agnostically so catalog version bumps don't break it.
Seed source: kb/seed_cwe.json, a short hand-written guide for Python-relevant
weaknesses so the tool works before the full catalog is indexed.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CweDoc:
    id: str           # "CWE-89"
    name: str
    text: str         # what gets embedded and shown to the reviewer
    source: str       # "seed" or "mitre"

    def metadata(self) -> dict:
        return {"cwe": self.id, "name": self.name, "source": self.source}


def load_seed(path: str | Path) -> list[CweDoc]:
    docs = []
    for e in json.loads(Path(path).read_text()):
        text = (f"{e['id']}: {e['name']}\n{e['summary']}\n"
                f"Python patterns: {'; '.join(e['python_patterns'])}\n"
                f"Mitigations: {'; '.join(e['mitigations'])}")
        docs.append(CweDoc(e["id"], e["name"], text, "seed"))
    return docs


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el) -> str:
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip() if el is not None else ""


def _child(el, name):
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def parse_cwe_xml(path: str | Path, max_chars: int = 2500) -> list[CweDoc]:
    docs = []
    for _, el in ET.iterparse(str(path), events=("end",)):
        if _local(el.tag) != "Weakness":
            continue
        if el.get("Status") == "Deprecated":
            el.clear()
            continue
        cid, name = f"CWE-{el.get('ID')}", el.get("Name", "")
        parts = [f"{cid}: {name}", _text(_child(el, "Description")), _text(_child(el, "Extended_Description"))]
        mits = _child(el, "Potential_Mitigations")
        if mits is not None:
            ms = [_text(_child(m, "Description")) for m in mits if _local(m.tag) == "Mitigation"]
            parts.append("Mitigations: " + " | ".join(x for x in ms if x))
        docs.append(CweDoc(cid, name, "\n".join(p for p in parts if p)[:max_chars], "mitre"))
        el.clear()
    return docs
