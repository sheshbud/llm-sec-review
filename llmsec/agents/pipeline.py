"""Multi-agent security review: triage -> (retrieve + review per chunk, in parallel) -> verify,
with one bounded self-reflection round where the verifier can send chunks back for a recheck.

Fail-open on agent errors: if triage or verification output is unusable, the pipeline
reviews/keeps more rather than less, because a silent miss is worse than a false positive.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..rag.chunk import Chunk, chunk_python, number_lines
from ..rag.retriever import Retriever, format_context
from ..tracing import Tracer
from . import prompts
from .findings import dedupe, normalize
from .jsonutil import extract_json


@dataclass
class PipelineConfig:
    triage_model: str = field(default_factory=lambda: os.environ.get("LLMSEC_TRIAGE_MODEL", "claude-haiku-5-5"))
    review_model: str = field(default_factory=lambda: os.environ.get("LLMSEC_REVIEW_MODEL", "claude-sonnet-5-5"))
    verify_model: str = field(default_factory=lambda: os.environ.get("LLMSEC_VERIFY_MODEL", "claude-sonnet-5-5"))
    use_rag: bool = True
    suspicion_threshold: float = 0.3
    max_workers: int = 4
    max_reflections: int = 1


class ReviewPipeline:
    def __init__(self, llm, tracer: Tracer, retriever: Retriever | None = None, config: PipelineConfig | None = None):
        self.llm = llm
        self.tracer = tracer
        self.retriever = retriever
        self.cfg = config or PipelineConfig()
        if self.cfg.use_rag and retriever is None:
            raise ValueError("use_rag=True requires a retriever")

    # ---- public -------------------------------------------------------
    def review_source(self, source: str, filename: str = "<input>") -> dict:
        n_lines = len(source.splitlines())
        with self.tracer.span("review_file", filename=filename) as root:
            chunks = chunk_python(source)
            by_id = {c.id: c for c in chunks}
            targets = self._triage(chunks, root.span_id)
            root.attrs["chunks"], root.attrs["reviewed"] = len(chunks), len(targets)

            candidates = self._review_many(targets, root.span_id)
            findings, recheck = self._verify(source, candidates, n_lines, root.span_id)

            for _ in range(self.cfg.max_reflections):
                todo = [(by_id[r["chunk"]], r.get("note", "")) for r in recheck if r.get("chunk") in by_id]
                if not todo:
                    break
                with self.tracer.span("reflection", parent=root.span_id) as refl:
                    refl.attrs["chunks"] = [c.id for c, _ in todo]
                    extra = self._review_many([(c, [note]) for c, note in todo], refl.span_id, note_mode=True)
                    new, recheck = self._verify(source, extra, n_lines, refl.span_id)
                    findings += new

        return {"file": filename, "findings": dedupe(findings), "metrics": self.tracer.summary()}

    # ---- agents -------------------------------------------------------
    def _triage(self, chunks: list[Chunk], parent: str) -> list[tuple[Chunk, list[str]]]:
        if not chunks:
            return []
        listing = "\n\n".join(f"### chunk {c.id} ({c.kind} {c.name})\n{c.numbered}" for c in chunks)
        text = self.llm.complete(model=self.cfg.triage_model, system=prompts.TRIAGE,
                                 user=f"<code>\n{listing}\n</code>", max_tokens=1500,
                                 span_name="triage", parent=parent)
        data = extract_json(text)
        rows = data.get("chunks") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return [(c, []) for c in chunks]  # fail open: review everything

        scores = {}
        for r in rows:
            if isinstance(r, dict) and r.get("id") in {c.id for c in chunks}:
                try:
                    s = float(r.get("suspicion", 1.0))
                except (TypeError, ValueError):
                    s = 1.0
                hyps = [str(h)[:200] for h in r.get("hypotheses", []) if isinstance(h, str)][:5]
                scores[r["id"]] = (s, hyps)
        # Chunks the triage agent skipped are reviewed (fail open).
        return [(c, scores.get(c.id, (1.0, []))[1]) for c in chunks
                if scores.get(c.id, (1.0, []))[0] >= self.cfg.suspicion_threshold]

    def _review_many(self, targets, parent: str, note_mode: bool = False) -> list[dict]:
        if not targets:
            return []
        with ThreadPoolExecutor(max_workers=self.cfg.max_workers) as pool:
            results = pool.map(lambda t: self._review_chunk(t[0], t[1], parent, note_mode), targets)
            return [f for r in results for f in r]

    def _review_chunk(self, chunk: Chunk, hyps: list[str], parent: str, note_mode: bool) -> list[dict]:
        context = "(retrieval disabled)"
        if self.cfg.use_rag:
            with self.tracer.span("retrieve", parent=parent, chunk=chunk.id) as s:
                hits = self.retriever.retrieve(chunk.numbered, hyps)
                s.attrs["hits"] = [h.id for h in hits]
            context = format_context(hits)
        label = "Verifier note" if note_mode else "Triage hypotheses"
        user = (f"<reference>\n{context}\n</reference>\n\n"
                f"{label}: {'; '.join(hyps) or 'none'}\n\n<code>\n{chunk.numbered}\n</code>")
        text = self.llm.complete(model=self.cfg.review_model, system=prompts.REVIEW, user=user,
                                 max_tokens=1500, span_name="review", parent=parent)
        data = extract_json(text)
        raw = data.get("findings", []) if isinstance(data, dict) else []
        # Line must fall inside the reviewed chunk; anything else is a hallucination.
        return [f for f in raw if isinstance(f, dict) and _in_range(f.get("line"), chunk.start, chunk.end)]

    def _verify(self, source: str, candidates: list[dict], n_lines: int, parent: str):
        normalized = [f for f in (normalize(c, n_lines) for c in candidates) if f]
        if not normalized:
            return [], []
        listing = "\n".join(f"[{i}] line {f['line']} {f['cwe']} {f['severity']}: {f['title']}"
                            for i, f in enumerate(normalized))
        user = (f"<code>\n{number_lines(source.splitlines(), 1)}\n</code>\n\n"
                f"Candidate findings:\n{listing}")
        text = self.llm.complete(model=self.cfg.verify_model, system=prompts.VERIFY, user=user,
                                 max_tokens=2000, span_name="verify", parent=parent)
        data = extract_json(text)
        if not isinstance(data, dict) or not isinstance(data.get("verdicts"), list):
            return normalized, []  # fail open: keep unverified findings

        verdicts = {v.get("index"): v for v in data["verdicts"] if isinstance(v, dict)}
        kept = []
        for i, f in enumerate(normalized):
            v = verdicts.get(i)
            if v is None or v.get("verdict") == "keep":
                kept.append(f)
            elif v.get("verdict") == "revise":
                revised = normalize({**f, **{k: v[k] for k in ("line", "cwe", "severity") if k in v}}, n_lines)
                kept.append(revised or f)
            # "drop" falls through
        recheck = [r for r in data.get("recheck", []) if isinstance(r, dict)]
        return kept, recheck


def _in_range(line, start: int, end: int) -> bool:
    try:
        return start <= int(line) <= end
    except (TypeError, ValueError):
        return False
