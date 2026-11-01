"""Hybrid retrieval: exact lookup of CWE IDs the triage agent named, plus semantic top-k."""
from __future__ import annotations

import re

from .store import Hit

CWE_ID = re.compile(r"CWE-\d{1,4}")


class Retriever:
    def __init__(self, store, embedder, k: int = 4):
        self.store = store
        self.embedder = embedder
        self.k = k

    def retrieve(self, code: str, hypotheses: list[str] | None = None) -> list[Hit]:
        hypotheses = hypotheses or []
        exact_ids = sorted({m for h in hypotheses for m in CWE_ID.findall(h)})
        hits: dict[str, Hit] = {h.id: h for h in self.store.get(exact_ids)}
        query = "\n".join(hypotheses) + "\n" + code[:4000]
        [vec] = self.embedder.embed([query], task_type="RETRIEVAL_QUERY")
        for h in self.store.query(vec, self.k):
            hits.setdefault(h.id, h)
        return list(hits.values())[: self.k + len(exact_ids)]


def format_context(hits: list[Hit]) -> str:
    if not hits:
        return "(no reference material retrieved)"
    return "\n\n".join(f"[{h.id}] {h.document}" for h in hits)
