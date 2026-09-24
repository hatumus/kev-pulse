"""Scheduler / cycle runner.

`run_cycle` is the one function that both the autonomous polling loop and
every read/write MCP tool call ultimately go through, so the two modes
(scheduled, and human/agent-driven via MCP) can never drift apart.
"""
from __future__ import annotations

import atexit
import logging
import os
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
    """Wires config -> watchers -> correlation -> guardrail -> adapter(s), and
    exposes the operations the MCP tools call directly (propose/launch/etc.)

    Supports one or two backend adapters at once (TVM and/or Tenable
    Security Center), keyed by backend name ("tvm" | "sc") in `adapters`.
    Every read/write method below takes an optional `backend` argument that
    picks which adapter to use for that one call; omitting it uses
    `primary_backend`. The autonomous loop (`run_cycle`/`run_forever`)
    always omits it deliberately -- it only ever targets the primary
    backend, even when a secondary is also configured, to keep the
    highest-risk code path (unattended scan launching) simple and
    predictable.
    """

    def __init__(
        self,
        config: Config,
        state: StateStore,
        adapters: dict[str, BackendAdapter],
        primary_backend: str,
    ):
        if primary_backend not in adapters:
            raise ValueError(
                f"primary_backend {primary_backend!r} is not in adapters "
                f"({sorted(adapters)!r})"
            )
        self.config = config
        self.state = state
        self.adapters = adapters
        self.primary_backend = primary_backend
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

    # -- backend selection ----------------------------------------------------

    def _adapter(self, backend: str | None = None) -> BackendAdapter:
        name = backend or self.primary_backend
        adapter = self.adapters.get(name)
        if adapter is None:
            configured = ", ".join(sorted(self.adapters)) or "(none)"
            raise ValueError(
                f"Backend {name!r} is not configured on this server. Configured "
                f"backend(s): {configured}."
            )
        return adapter

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

    def resolve_tags(self, plugin_family: str, backend: str | None = None) -> list[str]:
        return self._adapter(backend).resolve_tags_for_plugin(plugin_family, self.config.scan.tag_mapping)

    # -- write path -----------------------------------------------------------

    def propose_scan(self, match: CorrelationMatch, backend: str | None = None) -> str:
        adapter = self._adapter(backend)
        policy_template_id = self.config.scan.policy_template_id.get(adapter.name)
        if not policy_template_id:
            raise ValueError(
                f"No scan.policy_template_id configured for backend {adapter.name!r} -- "
                f"set scan.policy_template_id.{adapter.name} in config.yaml."
            )
        plugin = Plugin(
            plugin_id=match.plugin_id,
            name=match.plugin_name,
            family=match.plugin_family,
            cves=[match.cve_id],
            cvss3_base_score=match.cvss3_base_score,
        )
        tags = self.resolve_tags(match.plugin_family, backend=adapter.name)
        plan_id = str(uuid.uuid4())
        plan = adapter.build_scan_plan(
            plan_id=plan_id,
            cve_id=match.cve_id,
            plugin=plugin,
            tags=tags,
            policy_template_id=policy_template_id,
        )
        self.state.save_scan_plan(plan)
        self.state.record_audit(
            "proposed",
            cve_id=match.cve_id,
            plugin_id=match.plugin_id,
            tags=tags,
            backend=adapter.name,
            detail=match.reason,
        )
        return plan_id

    def launch_targeted_scan(self, plan_id: str, human_approved: bool = False) -> dict:
        plan_row = self.state.get_scan_plan(plan_id)
        if plan_row is None:
            raise KeyError(f"Unknown scan plan id: {plan_id}")
        if plan_row["consumed"]:
            raise RuntimeError(f"Scan plan {plan_id} was already consumed")

        # The plan already records which backend it was proposed against
        # (ScanPlan.backend), so launching always dispatches to that same
        # adapter -- never the caller's current default -- regardless of
        # which backend is primary at launch time.
        adapter = self._adapter(plan_row["backend"])

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
        result = adapter.launch_scan(plan)
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

    def get_scan_status(self, scan_id: str, backend: str | None = None) -> str:
        # Prefer an explicit backend; otherwise look up which backend
        # actually launched this scan_id from the audit trail (works
        # whether it was launched via the primary or a secondary backend);
        # fall back to primary_backend only if the audit trail has no
        # record of it (e.g. a scan id from outside kev-pulse).
        name = backend or self.state.get_backend_for_scan_id(scan_id) or self.primary_backend
        return self._adapter(name).get_scan_status(scan_id)

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
            # backend intentionally omitted on both calls below: the
            # autonomous loop always targets primary_backend only, even
            # when a secondary backend is configured for on-demand/manual
            # use via the MCP tools' explicit `backend` parameter.
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


def _pid_alive(pid: int) -> bool:
    """Best-effort, dependency-free liveness check, Windows + POSIX."""
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _release_watch_lock(lock_path: str, pid: int) -> None:
    try:
        if os.path.exists(lock_path):
            with open(lock_path, "r") as fh:
                if fh.read().strip() == str(pid):
                    os.remove(lock_path)
    except OSError:
        pass


def _acquire_watch_lock(db_path: str) -> bool:
    """Single-instance guard for the autonomous polling loop.

    It's possible for more than one kev-pulse process to end up running
    against the same state_db_path at once -- e.g. an MCP host that (for
    whatever reason) launches its stdio server child process more than
    once, or `kev-pulse watch` started alongside `kev-pulse serve` with
    guardrails.autonomous_in_serve: true. Two independent copies of
    run_forever() racing against the same StateStore is a real problem:
    the rate-limit check in GuardrailGate.evaluate() (count existing
    launches, then record a new one) is not atomic *across processes* --
    StateStore's lock only serializes access within one process -- so two
    processes could both pass the rate-limit check for the same cycle and
    both launch a scan when only one should have been allowed.

    This uses a PID lock file next to the state db (atomic O_CREAT|O_EXCL
    for the uncontended case) so only one live process ever runs the loop.
    A lock file whose owning PID is no longer running is treated as stale
    (e.g. the previous holder crashed or was killed without cleanup) and
    safely reclaimed. Returns True if this process acquired the lock and
    should run the loop, False if another live process already holds it.
    """
    lock_path = db_path + ".watch.lock"
    pid = os.getpid()

    def _try_create() -> bool:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w") as fh:
            fh.write(str(pid))
        atexit.register(_release_watch_lock, lock_path, pid)
        return True

    if _try_create():
        return True

    try:
        with open(lock_path, "r") as fh:
            existing_pid = int(fh.read().strip())
    except (OSError, ValueError):
        existing_pid = None

    if existing_pid and existing_pid != pid and _pid_alive(existing_pid):
        return False  # another live process already owns the loop

    # Stale lock (owner crashed/exited without cleanup, or the file was
    # unreadable) -- safe to reclaim.
    try:
        os.remove(lock_path)
    except OSError:
        pass
    return _try_create()  # if this loses a race too, just give up gracefully


def run_forever(pipeline: Pipeline, interval_hours: float) -> None:  # pragma: no cover - runtime loop
    if not _acquire_watch_lock(pipeline.state.db_path):
        logger.warning(
            "Another kev-pulse process already owns the autonomous polling loop "
            "(lock file %s.watch.lock is held by a live process) -- this process "
            "will NOT run a second, concurrent copy of it. This is expected if "
            "`watch` and `serve` (with guardrails.autonomous_in_serve: true), or "
            "two `serve` instances, end up running against the same "
            "state_db_path at the same time.",
            pipeline.state.db_path,
        )
        return

    logger.info(
        "Starting KEV-Pulse scheduler, interval=%sh, primary_backend=%s",
        interval_hours,
        pipeline.primary_backend,
    )
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
