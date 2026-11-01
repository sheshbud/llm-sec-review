"""Wire real components together. One Tracer per review keeps metrics per request."""
from __future__ import annotations

from functools import lru_cache

from ..llm import AnthropicClient
from ..rag.embed import GeminiEmbedder
from ..rag.retriever import Retriever
from ..rag.store import open_store
from ..tracing import Tracer
from .pipeline import PipelineConfig, ReviewPipeline


@lru_cache(maxsize=1)
def shared_store():
    return open_store()


def build_pipeline(tracer: Tracer, use_rag: bool = True) -> ReviewPipeline:
    retriever = Retriever(shared_store(), GeminiEmbedder(tracer=tracer)) if use_rag else None
    return ReviewPipeline(AnthropicClient(tracer), tracer, retriever, PipelineConfig(use_rag=use_rag))
