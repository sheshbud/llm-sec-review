"""Embedding backends.

GeminiEmbedder calls Google's embedding API over REST (stdlib only).
HashEmbedder is a deterministic bag-of-words hash used ONLY for offline tests.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import urllib.request

from ..tracing import Tracer

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


def _l2(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


class GeminiEmbedder:
    """task_type is RETRIEVAL_DOCUMENT when indexing and RETRIEVAL_QUERY when searching."""

    def __init__(self, tracer: Tracer | None = None, api_key: str | None = None,
                 model: str | None = None, dim: int = 768, batch: int = 100):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not set")
        self.model = model or os.environ.get("LLMSEC_EMBED_MODEL", "gemini-embedding-001")
        self.dim = dim
        self.batch = batch
        self.tracer = tracer

    def embed(self, texts: list[str], task_type: str = "RETRIEVAL_DOCUMENT") -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), self.batch):
            chunk = texts[i:i + self.batch]
            body = json.dumps({"requests": [{
                "model": f"models/{self.model}",
                "content": {"parts": [{"text": t[:8000]}]},
                "taskType": task_type,
                "outputDimensionality": self.dim,
            } for t in chunk]}).encode()
            req = urllib.request.Request(
                f"{GEMINI_BASE}/models/{self.model}:batchEmbedContents",
                data=body, method="POST",
                headers={"content-type": "application/json", "x-goog-api-key": self.api_key},
            )
            if self.tracer:
                with self.tracer.span("embed", n=len(chunk), task=task_type):
                    data = self._send(req)
            else:
                data = self._send(req)
            # Truncated-dimension Gemini vectors are not unit length; normalize for cosine.
            out.extend(_l2(e["values"]) for e in data["embeddings"])
        return out

    @staticmethod
    def _send(req) -> dict:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())


class HashEmbedder:
    """Test double. Not semantic: overlapping tokens produce similar vectors."""

    def __init__(self, dim: int = 256):
        self.dim = dim

    def embed(self, texts: list[str], task_type: str = "RETRIEVAL_DOCUMENT") -> list[list[float]]:
        vecs = []
        for t in texts:
            v = [0.0] * self.dim
            for tok in re.findall(r"[a-z0-9_]+", t.lower()):
                h = int(hashlib.md5(tok.encode()).hexdigest(), 16)  # non-security use: bucketing only
                v[h % self.dim] += 1.0
            vecs.append(_l2(v))
        return vecs
