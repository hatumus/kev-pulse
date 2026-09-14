import os
import tempfile
import unittest

from kev_pulse.correlation import CorrelationEngine
from kev_pulse.models import KevEntry, Plugin
from kev_pulse.state import StateStore


class CorrelationEngineTest(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.state = StateStore(self.db_path)
        self.engine = CorrelationEngine(self.state, min_cvss=7.0)

    def tearDown(self):
        self.state.close()
        os.remove(self.db_path)

    def test_plugin_arrives_first_then_kev(self):
        # Cycle 1: a high-severity plugin ships, CVE not yet in KEV -> no match.
        plugin = Plugin(
            plugin_id="100001",
            name="Example RCE Detection",
            family="Web Servers",
            cves=["CVE-2026-1234"],
            cvss3_base_score=9.8,
        )
        matches = self.engine.run_cycle([plugin], [])
        self.assertEqual(matches, [])

        # Cycle 2: CISA adds that CVE to KEV -> should now match.
        kev = KevEntry(
            cve_id="CVE-2026-1234",
            vendor_project="Example Corp",
            product="Example Server",
            vulnerability_name="Example RCE",
            date_added="2026-09-12",
        )
        matches = self.engine.run_cycle([], [kev])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].cve_id, "CVE-2026-1234")
        self.assertEqual(matches[0].plugin_id, "100001")
        self.assertEqual(matches[0].reason, "kev_new_plugin_already_exists")

    def test_kev_arrives_first_then_plugin(self):
        kev = KevEntry(
            cve_id="CVE-2026-5678",
            vendor_project="Example Corp",
            product="Example App",
            vulnerability_name="Example Bug",
            date_added="2026-09-10",
        )
        matches = self.engine.run_cycle([], [kev])
        self.assertEqual(matches, [])

        plugin = Plugin(
            plugin_id="200002",
            name="Example Bug Detection",
            family="Databases",
            cves=["CVE-2026-5678"],
            cvss3_base_score=8.1,
        )
        matches = self.engine.run_cycle([plugin], [])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].reason, "plugin_new_cve_already_kev")

    def test_below_threshold_is_filtered(self):
        plugin = Plugin(
            plugin_id="300003",
            name="Low severity detection",
            family="Misc",
            cves=["CVE-2026-9999"],
            cvss3_base_score=4.0,  # below min_cvss=7.0
        )
        kev = KevEntry(
            cve_id="CVE-2026-9999",
            vendor_project="X",
            product="Y",
            vulnerability_name="Z",
            date_added="2026-09-01",
        )
        # KEV first, plugin second -- still should be filtered by severity.
        self.engine.run_cycle([], [kev])
        matches = self.engine.run_cycle([plugin], [])
        self.assertEqual(matches, [])

    def test_no_duplicate_match_when_both_arrive_same_cycle(self):
        plugin = Plugin(
            plugin_id="400004",
            name="Simultaneous",
            family="Web Servers",
            cves=["CVE-2026-4242"],
            cvss3_base_score=9.0,
        )
        kev = KevEntry(
            cve_id="CVE-2026-4242",
            vendor_project="X",
            product="Y",
            vulnerability_name="Z",
            date_added="2026-09-14",
        )
        matches = self.engine.run_cycle([plugin], [kev])
        self.assertEqual(len(matches), 1)

    def test_repeated_cycle_does_not_rematch(self):
        plugin = Plugin(
            plugin_id="500005",
            name="Once",
            family="Web Servers",
            cves=["CVE-2026-7777"],
            cvss3_base_score=9.0,
        )
        kev = KevEntry(
            cve_id="CVE-2026-7777",
            vendor_project="X",
            product="Y",
            vulnerability_name="Z",
            date_added="2026-09-14",
        )
        first = self.engine.run_cycle([plugin], [kev])
        self.assertEqual(len(first), 1)
        # Same plugin/kev handed to the engine again (e.g. re-poll of the
        # same day) should not re-match, because upsert_* only returns
        # genuinely new rows.
        second = self.engine.run_cycle([plugin], [kev])
        self.assertEqual(second, [])


if __name__ == "__main__":
    unittest.main()
