import os
import tempfile
import unittest

from kev_pulse.models import ScanPlan
from kev_pulse.state import StateStore


class StateStoreTest(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.state = StateStore(self.db_path)

    def tearDown(self):
        self.state.close()
        os.remove(self.db_path)

    def test_cursor_roundtrip(self):
        self.assertIsNone(self.state.get_cursor("foo"))
        self.state.set_cursor("foo", "2026-09-14")
        self.assertEqual(self.state.get_cursor("foo"), "2026-09-14")
        self.state.set_cursor("foo", "2026-09-15")
        self.assertEqual(self.state.get_cursor("foo"), "2026-09-15")

    def test_scan_plan_roundtrip_and_consume(self):
        plan = ScanPlan(
            plan_id="plan-1",
            cve_id="CVE-2026-0001",
            plugin_id="1",
            plugin_name="Test Plugin",
            plugin_family="Web Servers",
            tags=["Internet-Facing"],
            backend="tvm",
            policy_template_id="tmpl-1",
        )
        self.state.save_scan_plan(plan)
        row = self.state.get_scan_plan("plan-1")
        self.assertIsNotNone(row)
        self.assertEqual(row["tags"], ["Internet-Facing"])
        self.assertEqual(row["consumed"], 0)

        self.state.mark_scan_plan_consumed("plan-1")
        row = self.state.get_scan_plan("plan-1")
        self.assertEqual(row["consumed"], 1)

    def test_audit_history_and_rate_limit(self):
        self.assertEqual(self.state.count_launches_since(24), 0)
        self.state.record_audit("launched", cve_id="CVE-1", scan_id="s1")
        self.state.record_audit("proposed", cve_id="CVE-2")
        self.assertEqual(self.state.count_launches_since(24), 1)

        history = self.state.get_audit_history(limit=10)
        self.assertEqual(len(history), 2)
        # newest first
        self.assertEqual(history[0]["event_type"], "proposed")
        self.assertEqual(history[1]["event_type"], "launched")


if __name__ == "__main__":
    unittest.main()
