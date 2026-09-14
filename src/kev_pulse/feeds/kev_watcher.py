"""KEV Watcher.

Fetches CISA's Known Exploited Vulnerabilities catalog (a plain JSON feed,
no authentication required) and returns every entry it contains. Diffing
against previously-seen entries is the StateStore's job (see
StateStore.upsert_kev), so this watcher stays a pure fetch-and-parse.
"""
from __future__ import annotations

from typing import Optional

import requests

from ..models import KevEntry

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class KevWatcher:
    def __init__(
        self,
        url: str = DEFAULT_KEV_URL,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.session = session or requests.Session()

    def poll(self) -> list[KevEntry]:
        resp = self.session.get(self.url, timeout=self.timeout)
        resp.raise_for_status()
        payload = resp.json()
        raw_entries = payload.get("vulnerabilities", [])
        return [_normalize(e) for e in raw_entries]


def _normalize(raw: dict) -> KevEntry:
    return KevEntry(
        cve_id=raw["cveID"],
        vendor_project=raw.get("vendorProject", ""),
        product=raw.get("product", ""),
        vulnerability_name=raw.get("vulnerabilityName", ""),
        date_added=raw.get("dateAdded", ""),
        required_action=raw.get("requiredAction", ""),
        due_date=raw.get("dueDate", ""),
    )
