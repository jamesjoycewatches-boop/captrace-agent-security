"""Command-line reports for reproducible authorization tests."""
import argparse
import json
from pathlib import Path

from .runner import load_scenario, run_scenario, run_suite
from .explorer import explore
from .audit import seal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay agent-tool permission revocation cases")
    parser.add_argument("--policy", choices=["runtime", "cached"], default="runtime",
                        help="runtime re-checks at dispatch; cached demonstrates TOCTOU failures")
    parser.add_argument("--scenario", type=Path,
                        help="custom JSON case; defaults to bundled scenarios")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--trace", action="store_true", help="include event traces in text mode")
    parser.add_argument("--explore", action="store_true",
                        help="exhaustively enumerate bounded plan/revoke/dispatch schedules")
    parser.add_argument("--calls", type=int, default=2,
                        help="number of planned calls in exploration (1..4, default 2)")
    parser.add_argument("--audit", action="store_true",
                        help="include SHA-256 hash-linked event ledger in reports")
    args = parser.parse_args(argv)
    if args.explore:
        if args.scenario:
            parser.error("--explore cannot be combined with --scenario")
        if not 1 <= args.calls <= 4:
            parser.error("--calls must be between 1 and 4")
        report = explore(policy=args.policy, calls=args.calls)
        if args.format == "json":
            print(json.dumps(report.as_dict(), indent=2))
        elif args.format == "markdown":
            print(f"# CapTrace bounded exploration\n\nPolicy: `{report.policy}`; calls: "
                  f"{report.calls}; schedules: {report.schedules}; "
                  f"violations: {report.violations}.\n")
            for witness in report.witnesses:
                print(f"- Counterexample: {' -> '.join(witness['order'])}")
        else:
            print(f"CapTrace explorer | policy={report.policy} | calls={report.calls} | "
                  f"schedules={report.schedules} | violations={report.violations}")
            for witness in report.witnesses:
                print("  witness: " + " -> ".join(witness["order"]))
        return 1 if report.violations else 0
    results = ([run_scenario(load_scenario(args.scenario), args.policy)]
               if args.scenario else run_suite(args.policy))
    passed = sum(case.passed for case in results)
    if args.format == "json":
        print(json.dumps({"policy": args.policy, "passed": passed,
                          "total": len(results),
                          "cases": [r.as_dict(include_audit=args.audit) for r in results]}, indent=2))
    elif args.format == "markdown":
        print(f"# CapTrace report\n\nPolicy: `{args.policy}`. Passed: {passed}/{len(results)}.\n")
        print("| Scenario | Result | Expected effects | Observed effects |")
        print("| --- | --- | --- | --- |")
        for item in results:
            print(f"| {item.name} | {'PASS' if item.passed else 'FAIL'} | "
                  f"{item.expected} | {item.observed} |")
    else:
        print(f"CapTrace | policy={args.policy} | {passed}/{len(results)} scenarios pass")
        for case in results:
            print(f"  {'PASS' if case.passed else 'FAIL'} {case.name}")
            if not case.passed:
                print(f"    expected={case.expected} observed={case.observed}")
            if args.audit:
                print(f"    audit sha256 head: {seal(case.timeline)['head']}")
            if args.trace:
                for event in case.timeline:
                    print("    " + json.dumps(event, sort_keys=True))
    return 0 if passed == len(results) and results else 1


if __name__ == "__main__":
    raise SystemExit(main())
