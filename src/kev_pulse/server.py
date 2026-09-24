"""MCP server entrypoint.

Exposes the pipeline in scheduler.py as MCP tools/resources so any
MCP-speaking client -- an analyst's AI assistant, another agent in a
multi-agent playbook, or just this project's own scheduler loop -- can
drive it through the same code path (see scheduler.Pipeline).

Run modes:
  kev-pulse serve --config config.yaml            # stdio (local)
  kev-pulse serve --config config.yaml --http     # streamable-http
  kev-pulse watch --config config.yaml            # autonomous loop, no MCP

If guardrails.autonomous_in_serve is true in config.yaml, `serve` ALSO
starts the same autonomous polling loop `watch` runs standalone, as a
daemon thread inside this process -- so the MCP server checks the feeds
and auto-launches guardrailed scans on its own schedule for as long as it
stays running, with no separate process required. It shares the same
Pipeline/StateStore as the MCP tools (StateStore is built for exactly this:
one sqlite connection with check_same_thread=False plus its own lock), so
this is safe to run at the same time tool calls are being served. This is
opt-in and defaults to off -- installing this MCP server never starts
launching scans in the background unless you explicitly set the flag.

Dual-backend support: config.yaml may configure both `backend` (primary)
and `backend.secondary` (the other of "tvm"/"sc") at once, so a single
running server can operate against both a Tenable Vulnerability Management
tenant and a Tenable Security Center instance without restarting or
reconfiguring. Every read/write tool below takes an optional `backend`
argument ("tvm" or "sc") to target a specific one for that one call;
omitting it uses the primary. The autonomous polling loop always targets
the primary backend only, regardless of what any individual tool call
passes -- see scheduler.Pipeline for why.
"""
from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
import threading

from mcp.server.fastmcp import FastMCP

from .backends import build_adapter
from .config import load_config
from .scheduler import Pipeline, run_forever
from .state import StateStore

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="kev-pulse",
    instructions=(
        "Watches Tenable's plugin feed and the CISA KEV catalog, correlates the two, "
        "resolves affected dynamic tags, and launches (or proposes) a scoped scan on "
        "Tenable Security Center and/or Tenable Vulnerability Management. Use "
        "correlate_exploited_plugins to see what's currently actionable, propose_scan "
        "to build a scan plan, and launch_targeted_scan(approve=true) to run it. "
        "launch_targeted_scan(approve=false) always returns without launching -- it "
        "does not exercise the auto_scan_allow_tags guardrail; that allow-list only "
        "ever auto-approves inside the autonomous polling loop (kev-pulse watch, or "
        "kev-pulse serve with guardrails.autonomous_in_serve: true), never through "
        "this MCP tool interface. Check the audit://trigger-history resource to see "
        "what the autonomous loop has proposed, launched, dry-run, or rejected. "
        "When both a TVM and a Security Center backend are configured (see "
        "list_configured_backends), most tools take an optional backend parameter "
        "('tvm' or 'sc') to target one explicitly; omitting it uses the primary "
        "backend. The autonomous polling loop only ever targets the primary backend, "
        "even when a secondary is also configured."
    ),
)

# Populated by main() before mcp.run() is called; module-level so the
# @mcp.tool functions (which FastMCP calls with no extra args) can reach it.
_pipeline: Pipeline | None = None


def _require_pipeline() -> Pipeline:
    if _pipeline is None:
        raise RuntimeError("Pipeline not initialized -- server was not started via main()")
    return _pipeline


@mcp.tool()
def list_configured_backends() -> dict:
    """List which Tenable backend(s) this server currently has credentials
    for, and which one is primary (used by the autonomous polling loop, and
    by every other tool below when its `backend` argument is omitted).
    Read-only."""
    pipeline = _require_pipeline()
    return {
        "primary_backend": pipeline.primary_backend,
        "configured_backends": sorted(pipeline.adapters.keys()),
    }


@mcp.tool()
def list_new_plugins(since: str | None = None) -> list[dict]:
    """List Tenable plugins created or updated on/after `since` (YYYY-MM-DD).
    Defaults to the watcher's saved cursor. Read-only. (The plugin feed is
    Tenable's shared plugin corpus, independent of which backend(s) are
    configured -- this tool has no backend parameter.)"""
    plugins = _require_pipeline().list_new_plugins(since=since)
    return [dataclasses.asdict(p) for p in plugins]


@mcp.tool()
def list_kev_deltas() -> list[str]:
    """List CVE IDs currently in the CISA KEV catalog that this server has
    not seen before. Read-only; does not mark them as seen."""
    return _require_pipeline().list_kev_deltas()


@mcp.tool()
def correlate_exploited_plugins(
    min_cvss: float | None = None, min_epss: float | None = None
) -> list[dict]:
    """Return the current actionable (plugin, CVE) set: a plugin exists to
    detect the CVE AND the CVE is in the KEV catalog, above the given
    severity threshold. Read-only."""
    matches = _require_pipeline().correlate(min_cvss=min_cvss, min_epss=min_epss)
    return [dataclasses.asdict(m) for m in matches]


@mcp.tool()
def resolve_affected_tags(plugin_family: str, backend: str | None = None) -> list[str]:
    """Return the customer's existing dynamic tags that apply to a given
    plugin family, per the configured tag_mapping. Read-only. Pass backend
    ('tvm' or 'sc') to check a specific backend's tags when more than one
    is configured; defaults to the primary backend."""
    return _require_pipeline().resolve_tags(plugin_family, backend=backend)


@mcp.tool()
def propose_scan(
    cve_id: str,
    plugin_id: str,
    plugin_name: str,
    plugin_family: str,
    reason: str = "manual",
    backend: str | None = None,
) -> str:
    """Build (but do not launch) a scan plan for a given CVE/plugin match.
    Returns a scan_plan_id to pass to launch_targeted_scan. Read-only /
    side-effect-free with respect to the customer's Tenable backend --
    it only resolves tags and writes a local plan record. Pass backend
    ('tvm' or 'sc') to target a specific backend when more than one is
    configured; defaults to the primary backend. The plan remembers
    whichever backend it was proposed against, so launch_targeted_scan
    always launches on that same backend regardless of what's primary at
    launch time."""
    from .models import CorrelationMatch

    match = CorrelationMatch(
        cve_id=cve_id,
        plugin_id=plugin_id,
        plugin_name=plugin_name,
        plugin_family=plugin_family,
        reason=reason,
    )
    return _require_pipeline().propose_scan(match, backend=backend)


@mcp.tool()
def launch_targeted_scan(scan_plan_id: str, approve: bool) -> dict:
    """Launch the scan described by a previously proposed plan. This is the
    ONLY tool in this server that mutates the customer's Tenable backend.
    Subject to the guardrail gate (dry_run, allow-list, rate limit) unless
    approve=true, which represents an explicit human decision and bypasses
    the allow-list -- but never the rate limit. Launches against whichever
    backend the plan was proposed against (see propose_scan); there is no
    backend parameter here."""
    if not approve:
        return {"launched": False, "reason": "approve must be true to launch a scan"}
    return _require_pipeline().launch_targeted_scan(scan_plan_id, human_approved=True)


@mcp.tool()
def get_scan_status(scan_id: str, backend: str | None = None) -> str:
    """Poll the status of a previously launched scan. Read-only. Pass
    backend ('tvm' or 'sc') if known; otherwise this looks up which backend
    actually launched scan_id from the audit trail, falling back to the
    primary backend if that lookup finds nothing."""
    return _require_pipeline().get_scan_status(scan_id, backend=backend)


@mcp.resource("audit://trigger-history")
def trigger_history() -> str:
    """The full history of proposed, launched, rejected, and dry-run events,
    newest first -- answers 'why did this scan run' after the fact. Each
    row's `backend` field records which backend that event was against."""
    import json

    rows = _require_pipeline().state.get_audit_history(limit=200)
    return json.dumps(rows, indent=2)


def _build_pipeline(config_path: str) -> Pipeline:
    config = load_config(config_path)
    state = StateStore(config.state_db_path)

    adapters = {config.backend.type: build_adapter(config.backend)}
    if config.secondary_backend is not None:
        adapters[config.secondary_backend.type] = build_adapter(config.secondary_backend)

    return Pipeline(
        config=config,
        state=state,
        adapters=adapters,
        primary_backend=config.backend.type,
    )


def main(argv: list[str] | None = None) -> None:
    global _pipeline

    parser = argparse.ArgumentParser(prog="kev-pulse")
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared flags for both subcommands. These must live on a parent parser
    # (rather than the top-level parser) so `kev-pulse serve --config x.yaml`
    # works -- argparse subparsers don't see flags defined only on the
    # top-level parser when those flags appear *after* the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    common.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )

    serve = sub.add_parser(
        "serve", help="Run as an MCP server (stdio by default)", parents=[common]
    )
    serve.add_argument(
        "--transport", default="stdio", choices=["stdio", "sse", "streamable-http"]
    )

    sub.add_parser(
        "watch", help="Run the autonomous polling loop with no MCP transport", parents=[common]
    )

    args = parser.parse_args(argv)

    # stderr alone isn't reliably visible when this runs as an MCP client's
    # child process (e.g. an MCPB extension) -- also write to a log file
    # next to config.yaml so the autonomous loop's activity (and any
    # exception inside it) can always be inspected directly.
    import os

    config_dir = os.path.dirname(os.path.abspath(args.config)) or "."
    log_path = os.path.join(config_dir, "kev_pulse.log")
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr), logging.FileHandler(log_path, encoding="utf-8")],
        # basicConfig() is a no-op if the root logger already has handlers
        # (e.g. attached somewhere in mcp's own import chain) -- force=True
        # makes sure our handlers (in particular the FileHandler) actually
        # get attached instead of silently doing nothing while still
        # creating an empty log file as a side effect of construction.
        force=True,
    )
    logger.info("kev-pulse starting: command=%s config=%s log_path=%s", args.command, args.config, log_path)

    _pipeline = _build_pipeline(args.config)
    logger.info(
        "Configured backend(s): %s (primary=%s)",
        sorted(_pipeline.adapters.keys()),
        _pipeline.primary_backend,
    )

    if args.command == "serve":
        if _pipeline.config.guardrails.autonomous_in_serve:
            interval = _pipeline.config.plugin_feed.poll_interval_hours
            logger.info(
                "guardrails.autonomous_in_serve is true -- starting background "
                "autonomous polling loop (interval=%sh, primary backend=%s) alongside "
                "the MCP server",
                interval,
                _pipeline.primary_backend,
            )
            watch_thread = threading.Thread(
                target=run_forever,
                args=(_pipeline,),
                kwargs={"interval_hours": interval},
                name="kev-pulse-watch",
                daemon=True,
            )
            watch_thread.start()
        mcp.run(transport=args.transport)
    elif args.command == "watch":
        run_forever(_pipeline, interval_hours=_pipeline.config.plugin_feed.poll_interval_hours)


if __name__ == "__main__":
    main()
