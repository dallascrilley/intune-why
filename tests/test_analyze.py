import unittest

from intune_why.analyze import SnapshotError, analyze, fix_plan

from helpers import device, failing, snapshot


class FixPlanTests(unittest.TestCase):
    def test_greedy_counts_devices_only_when_every_cause_is_fixed(self):
        plan = fix_plan({"a": {"x"}, "b": {"x", "y"}, "c": {"y"}, "d": {"z"}, "e": {"y"}})
        self.assertEqual([(s["cause"], s["newly_cleared"], s["cumulative_cleared"]) for s in plan],
                         [("y", 2, 2), ("x", 2, 4), ("z", 1, 5)])

    def test_progresses_when_no_single_fix_clears_a_device(self):
        plan = fix_plan({"a": {"x", "y"}, "b": {"x", "z"}})
        self.assertEqual(plan[0], {"cause": "x", "newly_cleared": 0, "cumulative_cleared": 0})
        self.assertEqual(plan[-1]["cumulative_cleared"], 2)


class AnalyzeTests(unittest.TestCase):
    def test_totals_unexplained_unmatched_and_stale(self):
        report = analyze(snapshot(
            [device("a"), device("b", last_sync="0001-01-01T00:00:00Z"), device("c", state="compliant"), device("d")],
            [failing("a", "P.BitLockerEnabled"), failing("b", "P.BitLockerEnabled", "error"),
             failing("b", "P.OsMinimumVersion"), failing("ghost", "P.BitLockerEnabled"),
             failing("c", "P.OsMinimumVersion", "compliant")]))
        t = report["totals"]
        self.assertEqual((t["devices"], t["needs_attention"], t["compliant"], t["unexplained"], t["unmatched_setting_states"]),
                         (4, 3, 1, 1, 1))
        bitlocker = next(c for c in report["causes"] if c["setting"] == "P.BitLockerEnabled")
        self.assertEqual((bitlocker["affected"], bitlocker["clears_alone"], bitlocker["not_recently_synced"]), (2, 1, 1))
        self.assertEqual(bitlocker["states"], {"nonCompliant": 1, "error": 1})
        self.assertEqual(report["unexplained"], ["d"])
        self.assertEqual(report["plan"][-1]["compliant_after"], 3)

    def test_duplicate_state_rows_count_once(self):
        report = analyze(snapshot([device("a")], [failing("a", "P.X"), failing("a", "P.X")]))
        self.assertEqual(report["causes"][0]["affected"], 1)

    def test_rejects_invalid_snapshots(self):
        for bad in ({"schema": "other"}, snapshot([device("a"), device("a")], []),
                    snapshot([device("a")], [{"device_id": "a"}]), snapshot([], [], collected_at="yesterday")):
            with self.assertRaises(SnapshotError):
                analyze(bad)


if __name__ == "__main__":
    unittest.main()
