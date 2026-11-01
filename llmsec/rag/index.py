"""Build the CWE vector index.

  python -m llmsec.rag.index --seed kb/seed_cwe.json
  python -m llmsec.rag.index --seed kb/seed_cwe.json --cwe-xml cwec_v4.xml
"""
from __future__ import annotations

import argparse

from ..tracing import Tracer
from .cwe import load_seed, parse_cwe_xml
from .embed import GeminiEmbedder
from .store import MemoryStore, open_store


def build(docs, store, embedder, batch: int = 100) -> int:
    # Seed docs win over MITRE docs for the same ID: they carry Python-specific patterns.
    by_id = {}
    for d in docs:
        if d.id not in by_id or d.source == "seed":
            by_id[d.id] = d
    docs = list(by_id.values())
    for i in range(0, len(docs), batch):
        part = docs[i:i + batch]
        vecs = embedder.embed([d.text for d in part], task_type="RETRIEVAL_DOCUMENT")
        store.upsert([d.id for d in part], vecs, [d.text for d in part], [d.metadata() for d in part])
    return len(docs)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="kb/seed_cwe.json")
    ap.add_argument("--cwe-xml")
    ap.add_argument("--store", default=None, help="chroma (default) or memory")
    ap.add_argument("--path", default=None)
    args = ap.parse_args()

    docs = load_seed(args.seed)
    if args.cwe_xml:
        docs += parse_cwe_xml(args.cwe_xml)
    tracer = Tracer()
    store = open_store(args.store, args.path)
    n = build(docs, store, GeminiEmbedder(tracer=tracer))
    if isinstance(store, MemoryStore):
        store.save(args.path or "kb/index.json")
    print(f"indexed {n} CWE entries; store now holds {store.count()}")
    print(tracer.summary()["by_stage"].get("embed"))


if __name__ == "__main__":
    main()
