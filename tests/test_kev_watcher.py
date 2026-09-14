import unittest
from unittest.mock import MagicMock

from kev_pulse.feeds.kev_watcher import KevWatcher


class KevWatcherTest(unittest.TestCase):
    def test_poll_parses_entries(self):
        fake_session = MagicMock()
        fake_response = MagicMock()
        fake_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1111",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Acme Widget RCE",
                    "dateAdded": "2026-09-10",
                    "requiredAction": "Apply updates",
                    "dueDate": "2026-10-01",
                }
            ]
        }
        fake_response.raise_for_status.return_value = None
        fake_session.get.return_value = fake_response

        watcher = KevWatcher(url="https://example.invalid/kev.json", session=fake_session)
        entries = watcher.poll()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].cve_id, "CVE-2026-1111")
        self.assertEqual(entries[0].vendor_project, "Acme")
        fake_session.get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
