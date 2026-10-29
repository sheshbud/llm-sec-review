"""Schema-layer tests. These run without an API key.

The point of this layer is that model output is untrusted, so the tests are mostly
about what gets rejected rather than what gets accepted.
"""
import unittest

from llmsec.schema import validate_findings, SchemaError


class TestValidateFindings(unittest.TestCase):
    def test_accepts_well_formed(self):
        out, dropped = validate_findings(
            {"findings": [{"line": 4, "cwe": "cwe-89", "severity": "HIGH",
                           "name": "sql-injection", "description": "concat into query"}]}, 10)
        self.assertEqual(dropped, 0)
        self.assertEqual(out[0]["cwe"], "CWE-89")      # normalized upper
        self.assertEqual(out[0]["severity"], "high")   # normalized lower

    def test_rejects_non_object(self):
        for bad in ([], "findings", 3, None):
            with self.assertRaises(SchemaError):
                validate_findings(bad, 10)

    def test_rejects_missing_findings_list(self):
        with self.assertRaises(SchemaError):
            validate_findings({"results": []}, 10)

    def test_caps_volume(self):
        with self.assertRaises(SchemaError):
            validate_findings({"findings": [{"line": 1, "cwe": "CWE-1"}] * 101}, 10)

    def test_drops_line_out_of_range(self):
        out, dropped = validate_findings(
            {"findings": [{"line": 999, "cwe": "CWE-89"}, {"line": 0, "cwe": "CWE-89"}]}, 10)
        self.assertEqual((out, dropped), ([], 2))

    def test_drops_malformed_cwe(self):
        out, dropped = validate_findings(
            {"findings": [{"line": 1, "cwe": "SQL injection"},
                          {"line": 1, "cwe": "CWE-"},
                          {"line": 1, "cwe": "CWE-12345"}]}, 10)
        self.assertEqual((out, dropped), ([], 3))

    def test_one_bad_finding_does_not_discard_the_rest(self):
        out, dropped = validate_findings(
            {"findings": [{"line": 1, "cwe": "CWE-89"}, "not-an-object"]}, 10)
        self.assertEqual(len(out), 1)
        self.assertEqual(dropped, 1)

    def test_unknown_severity_defaults_to_medium(self):
        out, _ = validate_findings(
            {"findings": [{"line": 1, "cwe": "CWE-89", "severity": "catastrophic"}]}, 10)
        self.assertEqual(out[0]["severity"], "medium")

    def test_truncates_long_free_text(self):
        out, _ = validate_findings(
            {"findings": [{"line": 1, "cwe": "CWE-89",
                           "name": "x" * 500, "description": "y" * 5000}]}, 10)
        self.assertEqual(len(out[0]["name"]), 80)
        self.assertEqual(len(out[0]["description"]), 400)


if __name__ == "__main__":
    unittest.main()
