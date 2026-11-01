Paste this into Claude Code from the llm-sec-review repo root, after copying in the new files.

---

I added an agentic RAG review path: llmsec/agents/, llmsec/rag/, llmsec/tracing.py, llmsec/llm.py,
llmsec/agentic_cli.py, llmsec/server.py, kb/, config/, tests/, RAG.md, Dockerfile.
Do not modify the new files' logic unless a test proves a bug. Tasks:

1. Run `python -m unittest discover -s tests -t .` and confirm all pass alongside the existing 9 schema tests.
2. Route the pipeline's final findings through the existing `validate_findings()` in llmsec/schema.py.
   Map fields if names differ (pipeline emits line, cwe, severity, title, rationale). Add a test.
3. Add an `agentic` and `agentic-norag` tool to llmsec/evaluate.py and the CLI so `evaluate` scores four
   configurations on all 19 labeled samples: Semgrep, single-call Claude (existing), agentic without RAG,
   agentic with RAG. Same detection / false-positive / injection-resistance metrics as today.
4. For the two agentic configs, also report mean latency, mean tokens/sec, total tokens, and cost per file
   from result["metrics"]. Save raw per-file results to results/agentic.json.
5. Build the index with the seed KB first, run the evaluation once, and print the comparison table.
   Do NOT tune prompts against the labels after seeing results; if you change anything, say so in README.
6. Add the table and the RAG.md architecture diagram to README. Report honest numbers even if RAG does not win.
