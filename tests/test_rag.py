import tempfile
import textwrap
import unittest
from pathlib import Path

from llmsec.rag.chunk import chunk_python
from llmsec.rag.cwe import load_seed, parse_cwe_xml
from llmsec.rag.embed import HashEmbedder
from llmsec.rag.index import build
from llmsec.rag.retriever import Retriever
from llmsec.rag.store import MemoryStore

SEED = Path(__file__).resolve().parent.parent / "kb" / "seed_cwe.json"

SAMPLE = textwrap.dedent('''\
    import sqlite3
    DB = "app.db"

    @decorator
    def get_user(name):
        conn = sqlite3.connect(DB)
        return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()

    class Svc:
        def run(self, cmd):
            import os
            os.system(cmd)

    if __name__ == "__main__":
        print(get_user("x"))
    ''')


def seeded_store():
    store = MemoryStore()
    build(load_seed(SEED), store, HashEmbedder())
    return store


class ChunkTests(unittest.TestCase):
    def test_chunks_cover_file_with_absolute_lines(self):
        chunks = chunk_python(SAMPLE)
        kinds = [(c.kind, c.name, c.start, c.end) for c in chunks]
        self.assertEqual(kinds, [
            ("module", "module-level", 1, 3),
            ("function", "get_user", 4, 7),     # decorator line included
            ("class", "Svc", 9, 12),
            ("module", "module-level", 13, 15),
        ])
        self.assertIn("   7 | ", chunks[1].numbered)

    def test_syntax_error_falls_back_to_windows(self):
        chunks = chunk_python("def broken(:\n" + "x = 1\n" * 130, window=60)
        self.assertEqual([c.kind for c in chunks], ["window"] * 3)
        self.assertEqual((chunks[2].start, chunks[2].end), (121, 131))

    def test_empty(self):
        self.assertEqual(chunk_python(""), [])


class StoreAndRetrievalTests(unittest.TestCase):
    def test_seed_loads_and_indexes(self):
        store = seeded_store()
        self.assertEqual(store.count(), 18)

    def test_semantic_query_ranks_relevant_cwe_first(self):
        store = seeded_store()
        [v] = HashEmbedder().embed(["pickle loads untrusted deserialization yaml load"])
        self.assertEqual(store.query(v, 1)[0].id, "CWE-502")

    def test_hybrid_retrieval_includes_exact_hypothesis_ids(self):
        r = Retriever(seeded_store(), HashEmbedder(), k=2)
        ids = [h.id for h in r.retrieve("x = 1", ["likely CWE-798 hard-coded key", "maybe CWE-9999"])]
        self.assertEqual(ids[0], "CWE-798")
        self.assertNotIn("CWE-9999", ids)
        self.assertLessEqual(len(ids), 3)

    def test_memory_store_roundtrip(self):
        store = seeded_store()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "idx.json"
            store.save(p)
            self.assertEqual(MemoryStore.load(p).count(), 18)

    def test_seed_overrides_mitre_for_same_id(self):
        from llmsec.rag.cwe import CweDoc
        store = MemoryStore()
        docs = [CweDoc("CWE-89", "SQLi", "mitre text", "mitre")] + load_seed(SEED)
        build(docs, store, HashEmbedder())
        self.assertEqual(store.get(["CWE-89"])[0].metadata["source"], "seed")


class CweXmlTests(unittest.TestCase):
    XML = textwrap.dedent('''\
        <?xml version="1.0"?>
        <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE">
          <Weaknesses>
            <Weakness ID="89" Name="SQL Injection" Status="Stable">
              <Description>Improper neutralization of SQL.</Description>
              <Extended_Description><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">More   detail.</xhtml:p></Extended_Description>
              <Potential_Mitigations>
                <Mitigation><Phase>Implementation</Phase><Description>Use parameterized queries.</Description></Mitigation>
              </Potential_Mitigations>
            </Weakness>
            <Weakness ID="1" Name="Old" Status="Deprecated"><Description>gone</Description></Weakness>
          </Weaknesses>
        </Weakness_Catalog>''')

    def test_parse(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cwe.xml"
            p.write_text(self.XML)
            docs = parse_cwe_xml(p)
        self.assertEqual([x.id for x in docs], ["CWE-89"])
        self.assertIn("More detail.", docs[0].text)
        self.assertIn("Mitigations: Use parameterized queries.", docs[0].text)


if __name__ == "__main__":
    unittest.main()
