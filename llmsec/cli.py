"""llm-sec-review CLI.

  python -m llmsec.cli baseline              run Semgrep over the benchmark
  python -m llmsec.cli review <file>         review one file with Claude
  python -m llmsec.cli evaluate              score both and compare
"""
import argparse
import json
import pathlib
import sys

from . import baseline, evaluate
from .schema import SchemaError

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "benchmark" / "samples"
LABELS = ROOT / "benchmark" / "labels.json"
RESULTS = ROOT / "benchmark" / "results"


def _labels():
    return json.loads(LABELS.read_text())


def cmd_baseline(args):
    res = baseline.run(SAMPLES)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "semgrep.json").write_text(json.dumps(res, indent=2))
    s = evaluate.score(res, _labels())
    print(evaluate.render("SEMGREP BASELINE (p/python + p/security-audit)", s))
    return 0


def cmd_review(args):
    from . import reviewer
    findings, meta = reviewer.review(args.path)
    print(json.dumps({"file": args.path, "findings": findings, "meta": meta}, indent=2))
    return 0


def cmd_llm(args):
    from . import reviewer
    res, errors = {}, {}
    for p in sorted(SAMPLES.glob("*.py")):
        try:
            findings, meta = reviewer.review(str(p))
            res[p.name] = findings
            note = "  (%d dropped by schema)" % meta["dropped_by_schema"] if meta["dropped_by_schema"] else ""
            print("  reviewed %-16s %d finding(s)%s" % (p.name, len(findings), note),
                  file=sys.stderr)
        except (SchemaError, Exception) as e:          # noqa: B014 - report, don't abort
            errors[p.name] = "%s: %s" % (type(e).__name__, e)
            res[p.name] = []
            print("  FAILED   %-16s %s" % (p.name, errors[p.name]), file=sys.stderr)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "llm.json").write_text(json.dumps(res, indent=2))
    if errors:
        (RESULTS / "llm_errors.json").write_text(json.dumps(errors, indent=2))
    s = evaluate.score(res, _labels())
    print(evaluate.render("LLM REVIEWER (Claude, schema-validated)", s))
    return 0


def cmd_evaluate(args):
    labels = _labels()
    summary = []
    for fname, title in (("semgrep.json", "SEMGREP BASELINE"),
                         ("llm.json", "LLM REVIEWER (Claude, schema-validated)")):
        p = RESULTS / fname
        if not p.exists():
            print("missing %s - run the matching command first" % p, file=sys.stderr)
            continue
        res = json.loads(p.read_text())
        strict = evaluate.score(res, labels)
        loose = evaluate.score(res, labels, equiv=True)
        print(evaluate.render(title + "  [exact CWE match]", strict))
        summary.append((title, strict, loose))

    if summary:
        print("\n" + "=" * 62)
        print("DETECTION: exact CWE match vs. CWE-equivalence")
        print("=" * 62)
        for title, strict, loose in summary:
            print("  %-42s %2d/%2d strict   %2d/%2d equiv"
                  % (title, strict["detection"]["caught"], strict["detection"]["total"],
                     loose["detection"]["caught"], loose["detection"]["total"]))
        print("\n  Equivalence classes applied:")
        for g in evaluate.CWE_EQUIV:
            print("    %s" % " == ".join(sorted(g)))
    return 0


def main():
    ap = argparse.ArgumentParser(prog="llm-sec-review")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline").set_defaults(fn=cmd_baseline)
    sub.add_parser("llm").set_defaults(fn=cmd_llm)
    sub.add_parser("evaluate").set_defaults(fn=cmd_evaluate)
    r = sub.add_parser("review")
    r.add_argument("path")
    r.set_defaults(fn=cmd_review)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
