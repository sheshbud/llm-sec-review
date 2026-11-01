"""HTTP service for Cloud Run.

POST /review  {"filename": "app.py", "source": "..."}  -> findings + per-stage metrics
GET  /healthz
Deploy with --no-allow-unauthenticated so only IAM-authorized callers reach it.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .tracing import Tracer

MAX_BODY = 256 * 1024


def make_handler(pipeline_factory):
    class Handler(BaseHTTPRequestHandler):
        server_version = "llmsec"

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/review":
                return self._send(404, {"error": "not found"})
            try:
                n = int(self.headers.get("content-length", "0"))
            except ValueError:
                return self._send(400, {"error": "bad content-length"})
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"error": f"body must be 1..{MAX_BODY} bytes"})
            try:
                req = json.loads(self.rfile.read(n))
                source = req["source"]
                if not isinstance(source, str):
                    raise TypeError
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": "expected JSON with a string 'source'"})
            filename = str(req.get("filename", "<input>"))[:200]
            use_rag = req.get("use_rag", True) is not False
            try:
                result = pipeline_factory(Tracer(), use_rag).review_source(source, filename)
            except Exception as e:  # don't leak internals to the caller
                self.log_error("review failed: %s", e)
                return self._send(502, {"error": "review failed"})
            self._send(200, result)

        def log_message(self, fmt, *args):  # one line per request, no bodies
            print(f"{self.command} {self.path} {fmt % args}", flush=True)

    return Handler


def main() -> None:
    from .agents.factory import build_pipeline

    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(build_pipeline)).serve_forever()


if __name__ == "__main__":
    main()
