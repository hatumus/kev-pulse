import unittest
from unittest.mock import MagicMock

from kev_pulse.feeds.plugin_watcher import PluginWatcher


def _make_session(pages):
    """pages: list of lists of raw plugin dicts, one per simulated page."""
    session = MagicMock()
    responses = []
    for page_items in pages:
        resp = MagicMock()
        resp.json.return_value = {"data": page_items}
        resp.raise_for_status.return_value = None
        responses.append(resp)
    session.get.side_effect = responses
    return session


class PluginWatcherTest(unittest.TestCase):
    def test_poll_normalizes_and_paginates(self):
        page1 = [
            {
                "id": 100001,
                "name": "Example RCE",
                "family_name": "Web Servers",
                "cve": ["CVE-2026-1234"],
                "cvss3_base_score": "9.8",
                "last_updated": "2026-09-14",
            }
        ] * 2  # exactly page_size=2, forces a second (empty) page fetch
        page2: list = []
        session = _make_session([page1, page2])

        watcher = PluginWatcher(url="https://example.invalid/plugins", page_size=2, session=session)
        plugins = watcher.poll(since="2026-09-14")

        self.assertEqual(len(plugins), 2)
        self.assertEqual(plugins[0].plugin_id, "100001")
        self.assertEqual(plugins[0].family, "Web Servers")
        self.assertEqual(plugins[0].cves, ["CVE-2026-1234"])
        self.assertEqual(plugins[0].cvss3_base_score, 9.8)
        self.assertEqual(session.get.call_count, 2)

    def test_poll_stops_on_short_page(self):
        page1 = [{"id": 1, "name": "A", "family_name": "F", "cve": ["CVE-1"]}]
        session = _make_session([page1])

        watcher = PluginWatcher(url="https://example.invalid/plugins", page_size=1000, session=session)
        plugins = watcher.poll(since="2026-09-14")

        self.assertEqual(len(plugins), 1)
        session.get.assert_called_once()

    def test_malformed_record_is_skipped_not_fatal(self):
        # missing everything except an id that will still parse fine --
        # verifies the normalizer tolerates sparse records.
        page1 = [{"id": 42}]
        session = _make_session([page1])
        watcher = PluginWatcher(url="https://example.invalid/plugins", page_size=1000, session=session)
        plugins = watcher.poll(since="2026-09-14")
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].plugin_id, "42")
        self.assertEqual(plugins[0].cves, [])


if __name__ == "__main__":
    unittest.main()
