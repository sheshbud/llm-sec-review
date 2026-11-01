FROM python:3.12-slim
WORKDIR /app
COPY requirements-rag.txt .
RUN pip install --no-cache-dir -r requirements-rag.txt
COPY llmsec ./llmsec
COPY config ./config
# Build kb/chroma locally first: python -m llmsec.rag.index --seed kb/seed_cwe.json [--cwe-xml ...]
COPY kb ./kb
RUN chown -R nobody /app/kb
USER nobody
ENV PORT=8080 LLMSEC_STORE=chroma LLMSEC_STORE_PATH=/app/kb/chroma PYTHONUNBUFFERED=1
CMD ["python", "-m", "llmsec.server"]
