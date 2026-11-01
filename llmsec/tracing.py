"""Per-call tracing and LLM-native metrics.

Every model or embedding call runs inside a span. A span records wall-clock
latency, token usage, tokens/sec, and cost (when prices are configured).
Spans are kept in memory and optionally appended to a JSONL file so a whole
review can be replayed and inspected after the fact.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

DEFAULT_PRICING_PATH = Path(__file__).resolve().parent.parent / "config" / "pricing.json"


def load_pricing(path: str | os.PathLike | None = None) -> dict:
    """Load per-model prices (USD per million tokens). Missing or null prices mean cost is unknown."""
    p = Path(path or os.environ.get("LLMSEC_PRICING", DEFAULT_PRICING_PATH))
    if not p.exists():
        return {}
    return json.loads(p.read_text()).get("models", {})


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_id: str | None
    name: str
    start: float
    end: float | None = None
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    error: str | None = None
    attrs: dict = field(default_factory=dict)

    @property
    def latency_s(self) -> float:
        return (self.end or time.perf_counter()) - self.start

    @property
    def tokens_per_sec(self) -> float | None:
        if not self.output_tokens or self.latency_s <= 0:
            return None
        return self.output_tokens / self.latency_s


class Tracer:
    def __init__(self, pricing: dict | None = None, sink_path: str | os.PathLike | None = None):
        self.trace_id = uuid.uuid4().hex
        self.pricing = pricing if pricing is not None else load_pricing()
        self.sink_path = Path(sink_path) if sink_path else None
        self.spans: list[Span] = []
        self._lock = threading.Lock()
        self._local = threading.local()

    def _stack(self) -> list[str]:
        if not hasattr(self._local, "stack"):
            self._local.stack = []
        return self._local.stack

    def current_span_id(self) -> str | None:
        stack = self._stack()
        return stack[-1] if stack else None

    @contextmanager
    def span(self, name: str, parent: str | None = None, **attrs) -> Iterator[Span]:
        """Open a span. In worker threads, pass parent= explicitly to keep the tree intact."""
        stack = self._stack()
        s = Span(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_id=parent if parent is not None else (stack[-1] if stack else None),
            name=name,
            start=time.perf_counter(),
            attrs=dict(attrs),
        )
        stack.append(s.span_id)
        try:
            yield s
        except Exception as exc:
            s.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            s.end = time.perf_counter()
            stack.pop()
            with self._lock:
                self.spans.append(s)
                if self.sink_path:
                    with self.sink_path.open("a") as f:
                        f.write(json.dumps(self._export(s)) + "\n")

    def record_llm(self, span: Span, model: str, input_tokens: int, output_tokens: int) -> None:
        span.model = model
        span.input_tokens = int(input_tokens or 0)
        span.output_tokens = int(output_tokens or 0)
        price = self.pricing.get(model) or {}
        pin, pout = price.get("input_per_mtok"), price.get("output_per_mtok")
        if pin is not None and pout is not None:
            span.cost_usd = (span.input_tokens * pin + span.output_tokens * pout) / 1_000_000

    def _export(self, s: Span) -> dict:
        d = asdict(s)
        d["latency_ms"] = round(s.latency_s * 1000, 1)
        d["tokens_per_sec"] = round(s.tokens_per_sec, 1) if s.tokens_per_sec else None
        d.pop("start"), d.pop("end")
        return d

    def summary(self) -> dict:
        """Aggregate metrics per span name plus a total. Cost is None if any LLM call lacks a price."""
        by_name: dict[str, dict] = {}
        for s in self.spans:
            agg = by_name.setdefault(s.name, {
                "calls": 0, "latency_ms": 0.0, "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0.0, "_gen_s": 0.0, "_cost_known": True, "errors": 0,
            })
            agg["calls"] += 1
            agg["latency_ms"] += s.latency_s * 1000
            agg["input_tokens"] += s.input_tokens
            agg["output_tokens"] += s.output_tokens
            agg["errors"] += 1 if s.error else 0
            if s.model:
                agg["_gen_s"] += s.latency_s
                if s.cost_usd is None:
                    agg["_cost_known"] = False
                else:
                    agg["cost_usd"] += s.cost_usd

        total = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "_cost_known": True, "llm_calls": 0}
        out: dict[str, dict] = {}
        for name, agg in by_name.items():
            gen_s = agg.pop("_gen_s")
            known = agg.pop("_cost_known")
            agg["latency_ms"] = round(agg["latency_ms"], 1)
            agg["tokens_per_sec"] = round(agg["output_tokens"] / gen_s, 1) if gen_s > 0 and agg["output_tokens"] else None
            agg["cost_usd"] = round(agg["cost_usd"], 6) if known else None
            out[name] = agg
            total["input_tokens"] += agg["input_tokens"]
            total["output_tokens"] += agg["output_tokens"]
            if gen_s > 0:
                total["llm_calls"] += agg["calls"]
                if agg["cost_usd"] is None:
                    total["_cost_known"] = False
                else:
                    total["cost_usd"] += agg["cost_usd"]
        total["cost_usd"] = round(total["cost_usd"], 6) if total.pop("_cost_known") else None
        root = [s for s in self.spans if s.parent_id is None]
        total["wall_ms"] = round(max((s.latency_s for s in root), default=0.0) * 1000, 1)
        return {"trace_id": self.trace_id, "by_stage": out, "total": total}
