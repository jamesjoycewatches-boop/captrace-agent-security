"""Command-line reports for reproducible authorization tests."""
import argparse
import json
from pathlib import Path

from .runner import load_scenario, run_scenario, run_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay agent-tool permission revocation cases")
    parser.add_argument("--policy", choices=["runtime", "cached"], default="runtime",
                        help="runtime re-checks at dispatch; cached demonstrates TOCTOU failures")
    parser.add_argument("--scenario", type=Path,
                        help="custom JSON case; defaults to bundled scenarios")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--trace", action="store_true", help="include event traces in text mode")
    args = parser.parse_args(argv)
    results = ([run_scenario(load_scenario(args.scenario), args.policy)]
               if args.scenario else run_suite(args.policy))
    passed = sum(case.passed for case in results)
    if args.format == "json":
        print(json.dumps({"policy": args.policy, "passed": passed,
                          "total": len(results),
                          "cases": [r.as_dict() for r in results]}, indent=2))
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
            if args.trace:
                for event in case.timeline:
                    print("    " + json.dumps(event, sort_keys=True))
    return 0 if passed == len(results) and results else 1


if __name__ == "__main__":
    raise SystemExit(main())
