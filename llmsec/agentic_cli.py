"""Agentic RAG reviewer CLI.

  python -m llmsec.agentic_cli review path/to/file.py [--no-rag] [--trace trace.jsonl]
"""
from __future__ import annotations

import argparse
import json
import pathlib

from .agents.factory import build_pipeline
from .tracing import Tracer


def main() -> None:
    ap = argparse.ArgumentParser(prog="llmsec.agentic_cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review")
    r.add_argument("file")
    r.add_argument("--no-rag", action="store_true", help="ablation: same agents, no retrieval")
    r.add_argument("--trace", help="append spans as JSONL to this file")
    args = ap.parse_args()

    path = pathlib.Path(args.file)
    tracer = Tracer(sink_path=args.trace)
    result = build_pipeline(tracer, use_rag=not args.no_rag).review_source(path.read_text(), str(path))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
