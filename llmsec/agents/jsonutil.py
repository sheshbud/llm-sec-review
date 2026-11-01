"""Pull a JSON value out of model text that may include prose or code fences."""
from __future__ import annotations

import json


def extract_json(text: str):
    """Return the first parseable JSON object or array, or None."""
    for open_c, close_c in (("{", "}"), ("[", "]")):
        a, z = text.find(open_c), text.rfind(close_c)
        if a != -1 and z > a:
            try:
                return json.loads(text[a:z + 1])
            except json.JSONDecodeError:
                continue
    return None
