"""Minimal Anthropic Messages client (stdlib only) that reports usage to a Tracer.

Any object with a matching .complete() signature can stand in for this class,
which is how the tests run the whole agent pipeline offline.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .tracing import Tracer

API_URL = "https://api.anthropic.com/v1/messages"
RETRYABLE = {408, 429, 500, 502, 503, 504, 529}


class LLMError(RuntimeError):
    pass


class AnthropicClient:
    def __init__(self, tracer: Tracer, api_key: str | None = None, timeout: float = 120.0, max_attempts: int = 3):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        self.tracer = tracer
        self.timeout = timeout
        self.max_attempts = max_attempts

    def complete(self, *, model: str, system: str, user: str, max_tokens: int = 2048,
                 span_name: str = "llm", parent: str | None = None) -> str:
        body = json.dumps({
            "model": model,
            "max_tokens": max_tokens,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode()
        with self.tracer.span(span_name, parent=parent) as span:
            data = self._post(body)
            usage = data.get("usage") or {}
            self.tracer.record_llm(span, model, usage.get("input_tokens", 0), usage.get("output_tokens", 0))
            span.attrs["stop_reason"] = data.get("stop_reason")
            return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")

    def _post(self, body: bytes) -> dict:
        last: Exception | None = None
        for attempt in range(self.max_attempts):
            req = urllib.request.Request(API_URL, data=body, method="POST", headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                last = LLMError(f"HTTP {e.code}: {e.read()[:300]!r}")
                if e.code not in RETRYABLE:
                    break
            except (urllib.error.URLError, TimeoutError) as e:
                last = LLMError(str(e))
            time.sleep(2 ** attempt)
        raise last or LLMError("request failed")
