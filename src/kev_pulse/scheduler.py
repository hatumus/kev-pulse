"""Scheduler / cycle runner.

`run_cycle` is the one function that both the autonomous polling loop and
every read/write MCP tool call ultimately go through, so the two modes
(scheduled, and human/agent-driven via MCP) can never drift apart.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from .backends.base import BackendAdapter
from .config import Config
from .correlation import CorrelationEngine
from .feeds.kev_watcher import KevWatcher
from .feeds.plugin_watcher import PluginWatcher
from .guardrails import GuardrailGate
from .models import CorrelationMatch, Plugin
from .state import StateStore

logger = logging.getLogger(__name__)

PLUGIN_CURSOR_KEY = "plugin_watcher.last_updated"


@dataclass
class CycleReport:
    new_plugin_count: int
    new_kev_count: int
    matches: list[CorrelationMatch]
    launched_scan_ids: list[str]
    proposed_plan_ids: list[str]


class Pipeline:
    """Wires config -> watchers -> correlation -> guardrail -> adapter, and
    exposes the operations the MCP tools call directly (propose/launch/etc.)
    """

    def __init__(self, config: Config, state: StateStore, adapter: BackendAdapter):
        self.config = config
        self.state = state
        self.adapter = adapter
        self.plugin_watcher = PluginWatcher(
            url=config.plugin_feed.url,
            access_key=config.plugin_feed.access_key,
            secret_key=config.plugin_feed.secret_key,
            page_size=config.plugin_feed.page_size,
        )
        self.kev_watcher = KevWatcher(url=config.kev_feed.url)
        self.correlation = CorrelationEngine(
            state=state,
            min_cvss=config.thresholds.min_cvss,
            min_epss=config.thresholds.min_epss,
        )
        self.guardrail = GuardrailGate(config.guardrails, state)

    # -- read tools ---------------------------------------------------------

    def list_new_plugins(self, since: str | None = None) -> list[Plugin]:
        cursor = since or self.state.get_cursor(PLUGIN_CURSOR_KEY)
        return self.plugin_watcher.poll(since=cursor)

    def list_kev_deltas(self) -> list[str]:
        entries = self.kev_watcher.poll()
        # peek without persisting: report what WOULD be new
        return [e.cve_id for e in entries if not self.state.is_kev(e.cve_id)]

    def correlate(self, min_cvss: float | None = None, min_epss: float | None = None) -> list[CorrelationMatch]:
        engine = CorrelationEngine(
            self.state,
            min_cvss=min_cvss if min_cvss is not None else self.config.thresholds.min_cvss,
            min_epss=min_epss if min_epss is not None else self.config.thresholds.min_epss,
        )
        plugins = self.plugin_watcher.poll(since=self.state.get_cursor(PLUGIN_CURSOR_KEY))
        kev_entries = self.kev_watcher.poll()
        return engine.run_cycle(plugins, kev_entries)

    def resolve_tags(self, plugin_family: str) -> list[str]:
        return self.adapter.resolve_tags_for_plugin(plugin_family, self.config.scan.tag_mapping)

    # -- write path -----------------------------------------------------------

    def propose_scan(self, match: CorrelationMatch) -> str:
        plugin = Plugin(
            plugin_id=match.plugin_id,
            name=match.plugin_name,
            family=match.plugin_family,
            cves=[match.cve_id],
            cvss3_base_score=match.cvss3_base_score,
        )
        tags = self.resolve_tags(match.plugin_family)
        plan_id = str(uuid.uuid4())
        plan = self.adapter.build_scan_plan(
            plan_id=plan_id,
            cve_id=match.cve_id,
            plugin=plugin,
            tags=tags,
            policy_template_id=self.config.scan.policy_template_id,
        )
        self.state.save_scan_plan(plan)
        self.state.record_audit(
            "proposed",
            cve_id=match.cve_id,
            plugin_id=match.plugin_id,
            tags=tags,
            backend=self.adapter.name,
            detail=match.reason,
        )
        return plan_id

    def launch_targeted_scan(self, plan_id: str, human_approved: bool = False) -> dict:
        plan_row = self.state.get_scan_plan(plan_id)
        if plan_row is None:
            raise KeyError(f"Unknown scan plan id: {plan_id}")
        if plan_row["consumed"]:
            raise RuntimeError(f"Scan plan {plan_id} was already consumed")

        decision = self.guardrail.evaluate(plan_row["tags"], human_approved=human_approved)
        if not decision.approved:
            self.state.record_audit(
                "dry_run" if decision.dry_run else "rejected",
                cve_id=plan_row["cve_id"],
                plugin_id=plan_row["plugin_id"],
                tags=plan_row["tags"],
                backend=plan_row["backend"],
                detail=decision.reason,
            )
            return {"launched": False, "reason": decision.reason}

        from .models import ScanPlan  # local import to avoid a cycle at module load

        plan = ScanPlan(
            plan_id=plan_row["plan_id"],
            cve_id=plan_row["cve_id"],
            plugin_id=plan_row["plugin_id"],
            plugin_name=plan_row["plugin_name"],
            plugin_family=plan_row.get("plugin_family", ""),
            tags=plan_row["tags"],
            backend=plan_row["backend"],
            policy_template_id=plan_row["policy_template_id"],
        )
        result = self.adapter.launch_scan(plan)
        self.state.mark_scan_plan_consumed(plan_id)
        self.state.record_audit(
            "launched",
            cve_id=plan.cve_id,
            plugin_id=plan.plugin_id,
            tags=plan.tags,
            backend=plan.backend,
            scan_id=result.scan_id,
            detail=decision.reason,
        )
        return {"launched": True, "scan_id": result.scan_id, "reason": decision.reason}

    def get_scan_status(self, scan_id: str) -> str:
        return self.adapter.get_scan_status(scan_id)

    # -- full autonomous cycle ------------------------------------------------

    def run_cycle(self) -> CycleReport:
        cursor = self.state.get_cursor(PLUGIN_CURSOR_KEY)
        plugins = self.plugin_watcher.poll(since=cursor)
        kev_entries = self.kev_watcher.poll()

        matches = self.correlation.run_cycle(plugins, kev_entries)

        from datetime import date

        self.state.set_cursor(PLUGIN_CURSOR_KEY, date.today().isoformat())

        launched: list[str] = []
        proposed: list[str] = []
        for match in matches:
            plan_id = self.propose_scan(match)
            outcome = self.launch_targeted_scan(plan_id, human_approved=False)
            if outcome["launched"]:
                launched.append(outcome["scan_id"])
            else:
                proposed.append(plan_id)

        return CycleReport(
            new_plugin_count=len(plugins),
            new_kev_count=len(kev_entries),
            matches=matches,
            launched_scan_ids=launched,
            proposed_plan_ids=proposed,
        )


def run_forever(pipeline: Pipeline, interval_hours: float) -> None:  # pragma: no cover - runtime loop
    logger.info("Starting KEV-Pulse scheduler, interval=%sh", interval_hours)
    while True:
        try:
            report = pipeline.run_cycle()
            logger.info(
                "Cycle complete: %d new plugins, %d kev entries, %d matches, "
                "%d launched, %d proposed",
                report.new_plugin_count,
                report.new_kev_count,
                len(report.matches),
                len(report.launched_scan_ids),
                len(report.proposed_plan_ids),
            )
        except Exception:
            logger.exception("Cycle failed; will retry next interval")
        time.sleep(interval_hours * 3600)
