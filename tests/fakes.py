"""Offline stand-ins so the full pipeline runs without API keys."""
import json
import threading


class FakeLLM:
    """Routes by span_name. Each route is a callable(user_prompt) -> str or a fixed string."""

    def __init__(self, tracer, routes):
        self.tracer = tracer
        self.routes = routes
        self.calls = []
        self._lock = threading.Lock()

    def complete(self, *, model, system, user, max_tokens=2048, span_name="llm", parent=None):
        with self._lock:
            self.calls.append({"span": span_name, "model": model, "user": user, "system": system})
        with self.tracer.span(span_name, parent=parent) as s:
            route = self.routes.get(span_name, "{}")
            out = route(user) if callable(route) else route
            self.tracer.record_llm(s, model, len(user) // 4, max(1, len(out) // 4))
            return out

    def count(self, span):
        return sum(1 for c in self.calls if c["span"] == span)


def js(obj):
    return "Sure, here you go:\n```json\n" + json.dumps(obj) + "\n```"
