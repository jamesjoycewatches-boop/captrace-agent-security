import json
import tempfile
import unittest
from pathlib import Path

from captrace.cli import main
from captrace.core import Engine
from captrace.runner import fixture_paths, load_scenario, run_scenario, run_suite


class AuthorizationTests(unittest.TestCase):
    def test_all_runtime_cases_pass(self):
        results = run_suite("runtime")
        self.assertGreaterEqual(len(results), 10)
        self.assertTrue(all(result.passed for result in results), results)

    def test_cached_snapshot_detects_revocation_failures(self):
        failures = [r.name for r in run_suite("cached") if not r.passed]
        self.assertIn("02-revoked-after-plan", failures)
        self.assertIn("03-expired-after-plan", failures)
        self.assertIn("04-delegated-parent-revoked", failures)

    def test_cannot_broaden_delegated_scope(self):
        engine = Engine()
        engine.grant(cap_id="root", principal="agent", resource="doc:42",
                     actions=["read"], expires_at=20)
        with self.assertRaisesRegex(ValueError, "broaden"):
            engine.delegate(parent_id="root", cap_id="child", principal="worker",
                            actions=["read", "delete"], expires_at=10, now=1)

    def test_child_cannot_outlive_parent(self):
        engine = Engine()
        engine.grant(cap_id="root", principal="agent", resource="doc:42",
                     actions=["read"], expires_at=20)
        with self.assertRaisesRegex(ValueError, "outlive"):
            engine.delegate(parent_id="root", cap_id="child", principal="worker",
                            actions=["read"], expires_at=30, now=1)

    def test_inactive_parent_cannot_delegate(self):
        engine = Engine()
        engine.grant(cap_id="root", principal="agent", resource="doc:42",
                     actions=["read"], expires_at=20)
        engine.revoke("root", now=2)
        with self.assertRaisesRegex(ValueError, "inactive parent"):
            engine.delegate(parent_id="root", cap_id="child", principal="worker",
                            actions=["read"], expires_at=10, now=3)

    def test_expiry_exclusive(self):
        engine = Engine()
        engine.grant(cap_id="root", principal="agent", resource="doc:42",
                     actions=["read"], expires_at=10)
        self.assertTrue(engine.check(cap_id="root", principal="agent",
                                     resource="doc:42", action="read", now=9).allowed)
        self.assertFalse(engine.check(cap_id="root", principal="agent",
                                      resource="doc:42", action="read", now=10).allowed)

    def test_effect_ledger_only_records_dispatched_allowed_calls(self):
        case = load_scenario(next(p for p in fixture_paths() if "10-two-calls" in p.name))
        result = run_scenario(case)
        self.assertEqual([e["call_id"] for e in result.effects], ["first"])

    def test_bad_step_order_rejected(self):
        case = load_scenario(fixture_paths()[0])
        case["steps"][1]["at"] = 0
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            run_scenario(case)

    def test_unexpected_extra_execution_fails(self):
        case = load_scenario(next(p for p in fixture_paths() if "02-revoked" in p.name))
        self.assertFalse(run_scenario(case, policy="cached").passed)

    def test_scenario_file_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid.json"
            path.write_text(json.dumps({"name": "bad"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing"):
                load_scenario(path)

    def test_cli_status(self):
        self.assertEqual(main(["--policy", "runtime"]), 0)
        self.assertEqual(main(["--policy", "cached"]), 1)


if __name__ == "__main__":
    unittest.main()
