"""Split Python source into reviewable chunks that keep absolute line numbers."""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class Chunk:
    id: str
    start: int   # 1-based, inclusive
    end: int     # inclusive
    kind: str    # function | class | module | window
    name: str
    numbered: str  # source with absolute line numbers, which is what models see


def number_lines(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + i:>4} | {line}" for i, line in enumerate(lines))


def chunk_python(source: str, window: int = 60) -> list[Chunk]:
    lines = source.splitlines()
    if not lines:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [Chunk(f"w{i // window}", i + 1, min(i + window, len(lines)), "window", f"lines {i + 1}+",
                      number_lines(lines[i:i + window], i + 1)) for i in range(0, len(lines), window)]

    spans: list[tuple[int, int, str, str]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            spans.append((start, node.end_lineno or node.lineno, kind, node.name))

    chunks: list[Chunk] = []
    cursor = 1

    def add_module(a: int, b: int) -> None:
        body = lines[a - 1:b]
        if any(l.strip() for l in body):
            chunks.append(Chunk(f"m{len(chunks)}", a, b, "module", "module-level", number_lines(body, a)))

    for start, end, kind, name in spans:
        if start > cursor:
            add_module(cursor, start - 1)
        chunks.append(Chunk(f"c{len(chunks)}", start, end, kind, name, number_lines(lines[start - 1:end], start)))
        cursor = end + 1
    if cursor <= len(lines):
        add_module(cursor, len(lines))
    return chunks
