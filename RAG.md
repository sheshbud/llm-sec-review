# Agentic RAG reviewer

Adds a multi-agent, retrieval-augmented review path next to the original single-call reviewer.

```
file ─► chunker (AST, absolute line numbers)
     ─► triage agent (cheap model): suspicion + candidate CWEs per chunk
     ─► per suspicious chunk, in parallel:
           retrieve: exact CWE-ID lookup + semantic top-k from the CWE vector index
           reviewer agent: findings grounded in retrieved CWE guidance
     ─► verifier agent: keep / revise / drop each finding, may request a recheck
     ─► one bounded self-reflection round on rechecked chunks
     ─► normalize + dedupe ─► findings + per-stage metrics
```

Design choices worth defending in an interview:
- **Fail open.** Unparseable triage reviews every chunk; unparseable verification keeps findings. A silent miss costs more than a false positive.
- **Untrusted model output.** Findings outside the reviewed chunk's line range are discarded; every field is validated.
- **Untrusted code.** Every agent's system prompt treats code comments as data, which is what the injection samples test.
- **Hybrid retrieval.** Exact IDs from triage guarantee the named CWE is in context; semantic search catches what triage missed.
- **Observability.** Every call is a span: latency, tokens in/out, tokens/sec, cost. `--trace` writes JSONL.

## Setup

```bash
pip install -r requirements-rag.txt
export ANTHROPIC_API_KEY=...        # never commit
export GEMINI_API_KEY=...           # Google AI Studio key, used for embeddings
```

Fill `config/pricing.json` from Anthropic's pricing page, or cost reports as `null`.

## Build the index

```bash
python -m llmsec.rag.index --seed kb/seed_cwe.json
# optional, full MITRE catalog (download cwec_latest.xml.zip from cwe.mitre.org, unzip):
python -m llmsec.rag.index --seed kb/seed_cwe.json --cwe-xml cwec_v4.xx.xml
```

## Run

```bash
python -m llmsec.agentic_cli review benchmark/samples/sqli.py --trace trace.jsonl
python -m llmsec.agentic_cli review benchmark/samples/sqli.py --no-rag   # ablation
```

## Tests (offline, no keys)

```bash
python -m unittest discover -s tests -t .
```

## Deploy to Cloud Run

```bash
gcloud services enable run.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com
printf %s "$ANTHROPIC_API_KEY" | gcloud secrets create anthropic-key --data-file=-
printf %s "$GEMINI_API_KEY"    | gcloud secrets create gemini-key --data-file=-
# grant the runtime service account roles/secretmanager.secretAccessor on both secrets

gcloud run deploy llm-sec-review --source . --region us-east1 \
  --no-allow-unauthenticated --memory 1Gi \
  --set-secrets ANTHROPIC_API_KEY=anthropic-key:latest,GEMINI_API_KEY=gemini-key:latest

curl -s -X POST "$(gcloud run services describe llm-sec-review --region us-east1 --format 'value(status.url)')/review" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "content-type: application/json" \
  -d "$(python3 -c 'import json,sys;print(json.dumps({"filename":"x.py","source":open(sys.argv[1]).read()}))' benchmark/samples/sqli.py)"
```
