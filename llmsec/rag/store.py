"""Vector stores with one interface: upsert, query, get.

ChromaStore is the real vector database (persistent, HNSW, cosine).
MemoryStore is a dependency-free exact-search fallback used in tests.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Hit:
    id: str
    document: str
    metadata: dict
    score: float  # cosine similarity, higher is closer


class MemoryStore:
    def __init__(self):
        self._rows: dict[str, tuple[list[float], str, dict]] = {}

    def upsert(self, ids, vectors, documents, metadatas) -> None:
        for i, v, d, m in zip(ids, vectors, documents, metadatas):
            self._rows[i] = (v, d, m)

    def query(self, vector: list[float], k: int = 4) -> list[Hit]:
        scored = [Hit(i, d, m, sum(a * b for a, b in zip(vector, v))) for i, (v, d, m) in self._rows.items()]
        return sorted(scored, key=lambda h: h.score, reverse=True)[:k]

    def get(self, ids: list[str]) -> list[Hit]:
        return [Hit(i, self._rows[i][1], self._rows[i][2], 1.0) for i in ids if i in self._rows]

    def count(self) -> int:
        return len(self._rows)

    def save(self, path: str | os.PathLike) -> None:
        Path(path).write_text(json.dumps({i: [v, d, m] for i, (v, d, m) in self._rows.items()}))

    @classmethod
    def load(cls, path: str | os.PathLike) -> "MemoryStore":
        s = cls()
        for i, (v, d, m) in json.loads(Path(path).read_text()).items():
            s._rows[i] = (v, d, m)
        return s


class ChromaStore:
    def __init__(self, path: str | os.PathLike, collection: str = "cwe"):
        import chromadb  # optional dependency, see requirements-rag.txt

        self._client = chromadb.PersistentClient(path=str(path))
        self._col = self._client.get_or_create_collection(collection, metadata={"hnsw:space": "cosine"})

    def upsert(self, ids, vectors, documents, metadatas) -> None:
        self._col.upsert(ids=list(ids), embeddings=list(vectors), documents=list(documents), metadatas=list(metadatas))

    def query(self, vector: list[float], k: int = 4) -> list[Hit]:
        r = self._col.query(query_embeddings=[vector], n_results=k)
        return [Hit(i, d, m or {}, 1.0 - dist) for i, d, m, dist in
                zip(r["ids"][0], r["documents"][0], r["metadatas"][0], r["distances"][0])]

    def get(self, ids: list[str]) -> list[Hit]:
        if not ids:
            return []
        r = self._col.get(ids=ids)
        return [Hit(i, d, m or {}, 1.0) for i, d, m in zip(r["ids"], r["documents"], r["metadatas"])]

    def count(self) -> int:
        return self._col.count()


def open_store(kind: str | None = None, path: str | None = None):
    kind = kind or os.environ.get("LLMSEC_STORE", "chroma")
    path = path or os.environ.get("LLMSEC_STORE_PATH", "kb/chroma")
    if kind == "chroma":
        return ChromaStore(path)
    if kind == "memory":
        return MemoryStore.load(path) if Path(path).exists() else MemoryStore()
    raise ValueError(f"unknown store kind: {kind}")
