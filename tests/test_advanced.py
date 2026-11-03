import copy
import io
import json
import unittest
from contextlib import redirect_stdout

from captrace.audit import seal, verify
from captrace.cli import main
from captrace.explorer import build_case, explore, schedules
from captrace.runner import run_scenario, run_suite


class AuditTests(unittest.TestCase):
    def test_repeatable_audit_head(self):
        events = [{"at": 0, "kind": "grant"}, {"at": 1, "kind": "revoke"}]
        first = seal(events)
        self.assertEqual(first, seal(events))
        self.assertTrue(verify(first, trusted_head=first["head"]))

    def test_tamper_detection(self):
        original = seal([{"at": 1, "kind": "plan"}, {"at": 2, "kind": "revoke"}])
        trusted_head = original["head"]
        for modified in ("edit", "delete", "reorder", "forge_head"):
            ledger = copy.deepcopy(original)
            if modified == "edit":
                ledger["entries"][0]["event"]["kind"] = "dispatch"
            elif modified == "delete":
                ledger["entries"].pop()
            elif modified == "reorder":
                ledger["entries"].reverse()
            else:
                ledger["head"] = "a" * 64
            self.assertFalse(verify(ledger, trusted_head=trusted_head), modified)

    def test_empty_and_invalid_audit(self):
        ledger = seal([])
        self.assertTrue(verify(ledger, trusted_head=ledger["head"]))
        self.assertFalse(verify({"entries": []}, trusted_head=ledger["head"]))

    def test_scenario_json_audit(self):
        result = run_suite()[0]
        data = result.as_dict(include_audit=True)
        self.assertTrue(verify(data["audit"], trusted_head=data["audit"]["head"]))
        self.assertNotIn("audit", result.as_dict())


class BoundedExplorationTests(unittest.TestCase):
    def test_schedule_counts(self):
        self.assertEqual([len(list(schedules(n))) for n in (1, 2, 3)], [3, 30, 630])

    def test_valid_schedule_order(self):
        for schedule in schedules(2):
            for i in (0, 1):
                self.assertLess(schedule.index(f"plan:{i}"),
                                schedule.index(f"dispatch:{i}"))
            self.assertEqual(schedule.count("revoke"), 1)

    def test_safe_policy_exhaustive(self):
        for calls in (1, 2, 3):
            result = explore(calls=calls, policy="runtime")
            self.assertEqual(result.violations, 0)
            self.assertGreater(result.schedules, 0)

    def test_cached_policy_has_replayable_witness(self):
        result = explore(calls=2, policy="cached")
        self.assertGreater(result.violations, 0)
        self.assertLess(result.violations, result.schedules)
        witness = result.witnesses[0]
        self.assertFalse(run_scenario(witness["replay"], "cached").passed)
        self.assertTrue(run_scenario(witness["replay"], "runtime").passed)

    def test_explore_bounds_and_policy_validation(self):
        for bad in (0, 5, True, 1.4):
            with self.assertRaises(ValueError):
                list(schedules(bad))
        with self.assertRaises(ValueError):
            explore(policy="unknown")

    def test_cli_explore_json_and_exit_codes(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["--explore", "--calls", "2", "--format", "json"]), 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["violations"], 0)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--explore", "--policy", "cached"]), 1)

    def test_cli_audit_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["--format", "json", "--audit"]), 0)
        result = json.loads(buf.getvalue())
        for case in result["cases"]:
            ledger = case["audit"]
            self.assertTrue(verify(ledger, trusted_head=ledger["head"]))


if __name__ == "__main__":
    unittest.main()
