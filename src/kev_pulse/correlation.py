"""Correlation Engine.

A (plugin, CVE) pair is actionable the moment BOTH of these are true,
regardless of which happened first:
  - Tenable has a plugin that detects the CVE, and
  - the CVE is a confirmed, in-the-wild exploited vulnerability (present in
    the KEV catalog, or whatever feed(s) are configured).

Two independent directions therefore both have to be checked every cycle:
  1. plugin-arrived-first:  a brand new/updated plugin covers a CVE that was
     already sitting in the KEV catalog from a previous cycle.
  2. kev-arrived-first:     a CVE that just landed in KEV is already covered
     by a plugin Tenable shipped a while ago.

A severity/EPSS threshold is applied on top, since not every KEV entry
necessarily warrants an unscheduled scan for every customer.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .models import CorrelationMatch, KevEntry, Plugin
from .state import StateStore


class CorrelationEngine:
    def __init__(self, state: StateStore, min_cvss: float = 7.0, min_epss: Optional[float] = None):
        self.state = state
        self.min_cvss = min_cvss
        self.min_epss = min_epss

    def run_cycle(
        self,
        new_plugins: Iterable[Plugin],
        new_kev_entries: Iterable[KevEntry],
    ) -> list[CorrelationMatch]:
        new_plugins = list(new_plugins)
        new_kev_entries = list(new_kev_entries)

        # Persist first -- both upserts return only what's genuinely new,
        # and every downstream lookup (is_kev / get_plugins_for_cve) needs
        # to see the freshly-written rows.
        new_plugin_cve_pairs = self.state.upsert_plugins(new_plugins)
        new_kev_cve_ids = self.state.upsert_kev(new_kev_entries)

        matches: list[CorrelationMatch] = []

        # Direction 1: plugin arrived first (or simultaneously), CVE was
        # already known-exploited.
        for cve_id, plugin in new_plugin_cve_pairs:
            if self.state.is_kev(cve_id):
                matches.append(self._to_match(cve_id, plugin, "plugin_new_cve_already_kev"))

        # Direction 2: KEV entry just landed, older plugin(s) already cover it.
        already_matched = {(m.cve_id, m.plugin_id) for m in matches}
        for cve_id in new_kev_cve_ids:
            for row in self.state.get_plugins_for_cve(cve_id):
                key = (cve_id, row["plugin_id"])
                if key in already_matched:
                    continue
                plugin = Plugin(
                    plugin_id=row["plugin_id"],
                    name=row["plugin_name"] or "",
                    family=row["family"] or "",
                    cves=[cve_id],
                    cvss3_base_score=row["cvss3_base_score"],
                    last_updated=row["last_updated"],
                )
                matches.append(self._to_match(cve_id, plugin, "kev_new_plugin_already_exists"))
                already_matched.add(key)

        return [m for m in matches if self._meets_threshold(m)]

    def _to_match(self, cve_id: str, plugin: Plugin, reason: str) -> CorrelationMatch:
        return CorrelationMatch(
            cve_id=cve_id,
            plugin_id=plugin.plugin_id,
            plugin_name=plugin.name,
            plugin_family=plugin.family,
            reason=reason,
            cvss3_base_score=plugin.cvss3_base_score,
            epss=None,  # populate here if/when an EPSS enrichment source is wired in
        )

    def _meets_threshold(self, match: CorrelationMatch) -> bool:
        if match.cvss3_base_score is not None and match.cvss3_base_score < self.min_cvss:
            return False
        if self.min_epss is not None and match.epss is not None and match.epss < self.min_epss:
            return False
        return True
