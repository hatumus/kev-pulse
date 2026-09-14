import os
import tempfile
import unittest

from kev_pulse.config import GuardrailConfig
from kev_pulse.guardrails import GuardrailGate
from kev_pulse.state import StateStore


class GuardrailGateTest(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.state = StateStore(self.db_path)

    def tearDown(self):
        self.state.close()
        os.remove(self.db_path)

    def test_dry_run_blocks_auto_launch(self):
        cfg = GuardrailConfig(dry_run=True, auto_scan_allow_tags=["Internet-Facing"])
        gate = GuardrailGate(cfg, self.state)
        decision = gate.evaluate(["Internet-Facing"], human_approved=False)
        self.assertFalse(decision.approved)
        self.assertTrue(decision.dry_run)

    def test_dry_run_does_not_block_human_approval(self):
        cfg = GuardrailConfig(dry_run=True, auto_scan_allow_tags=[])
        gate = GuardrailGate(cfg, self.state)
        decision = gate.evaluate(["Anything"], human_approved=True)
        self.assertTrue(decision.approved)

    def test_allow_list_permits_auto_launch(self):
        cfg = GuardrailConfig(dry_run=False, auto_scan_allow_tags=["Internet-Facing"])
        gate = GuardrailGate(cfg, self.state)
        decision = gate.evaluate(["Internet-Facing", "Other-Tag"], human_approved=False)
        self.assertTrue(decision.approved)

    def test_tags_not_on_allow_list_require_human(self):
        cfg = GuardrailConfig(dry_run=False, auto_scan_allow_tags=["Internet-Facing"])
        gate = GuardrailGate(cfg, self.state)
        decision = gate.evaluate(["Some-Other-Tag"], human_approved=False)
        self.assertFalse(decision.approved)

    def test_rate_limit_blocks_even_with_human_approval(self):
        cfg = GuardrailConfig(dry_run=False, auto_scan_allow_tags=["Internet-Facing"], max_launches_per_window=2, window_hours=24)
        gate = GuardrailGate(cfg, self.state)
        self.state.record_audit("launched", cve_id="CVE-1", scan_id="s1")
        self.state.record_audit("launched", cve_id="CVE-2", scan_id="s2")
        decision = gate.evaluate(["Internet-Facing"], human_approved=True)
        self.assertFalse(decision.approved)
        self.assertIn("rate limit", decision.reason)


if __name__ == "__main__":
    unittest.main()
