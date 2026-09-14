"""MCP server entrypoint.

Exposes the pipeline in scheduler.py as MCP tools/resources so any
MCP-speaking client -- an analyst's AI assistant, another agent in a
multi-agent playbook, or just this project's own scheduler loop -- can
drive it through the same code path (see scheduler.Pipeline).

Run modes:
  kev-pulse serve --config config.yaml            # stdio (local)
  kev-pulse serve --config config.yaml --http     # streamable-http
  kev-pulse watch --config config.yaml            # autonomous loop, no MCP
"""
from __future__ import annotations

import argparse
import dataclasses
import logging
import sys

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
        "Tenable Security Center or Tenable Vulnerability Management. Use "
        "correlate_exploited_plugins to see what's currently actionable, propose_scan "
        "to build a scan plan, and launch_targeted_scan(approve=true) to run it."
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
def list_new_plugins(since: str | None = None) -> list[dict]:
    """List Tenable plugins created or updated on/after `since` (YYYY-MM-DD).
    Defaults to the watcher's saved cursor. Read-only."""
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
def resolve_affected_tags(plugin_family: str) -> list[str]:
    """Return the customer's existing dynamic tags that apply to a given
    plugin family, per the configured tag_mapping. Read-only."""
    return _require_pipeline().resolve_tags(plugin_family)


@mcp.tool()
def propose_scan(
    cve_id: str, plugin_id: str, plugin_name: str, plugin_family: str, reason: str = "manual"
) -> str:
    """Build (but do not launch) a scan plan for a given CVE/plugin match.
    Returns a scan_plan_id to pass to launch_targeted_scan. Read-only /
    side-effect-free with respect to the customer's Tenable backend --
    it only resolves tags and writes a local plan record."""
    from .models import CorrelationMatch

    match = CorrelationMatch(
        cve_id=cve_id,
        plugin_id=plugin_id,
        plugin_name=plugin_name,
        plugin_family=plugin_family,
        reason=reason,
    )
    return _require_pipeline().propose_scan(match)


@mcp.tool()
def launch_targeted_scan(scan_plan_id: str, approve: bool) -> dict:
    """Launch the scan described by a previously proposed plan. This is the
    ONLY tool in this server that mutates the customer's Tenable backend.
    Subject to the guardrail gate (dry_run, allow-list, rate limit) unless
    approve=true, which represents an explicit human decision and bypasses
    the allow-list -- but never the rate limit."""
    if not approve:
        return {"launched": False, "reason": "approve must be true to launch a scan"}
    return _require_pipeline().launch_targeted_scan(scan_plan_id, human_approved=True)


@mcp.tool()
def get_scan_status(scan_id: str) -> str:
    """Poll the status of a previously launched scan. Read-only."""
    return _require_pipeline().get_scan_status(scan_id)


@mcp.resource("audit://trigger-history")
def trigger_history() -> str:
    """The full history of proposed, launched, rejected, and dry-run events,
    newest first -- answers 'why did this scan run' after the fact."""
    import json

    rows = _require_pipeline().state.get_audit_history(limit=200)
    return json.dumps(rows, indent=2)


def _build_pipeline(config_path: str) -> Pipeline:
    config = load_config(config_path)
    state = StateStore(config.state_db_path)
    adapter = build_adapter(config.backend)
    return Pipeline(config=config, state=state, adapter=adapter)


def main(argv: list[str] | None = None) -> None:
    global _pipeline

    parser = argparse.ArgumentParser(prog="kev-pulse")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run as an MCP server (stdio by default)")
    serve.add_argument(
        "--transport", default="stdio", choices=["stdio", "sse", "streamable-http"]
    )

    sub.add_parser("watch", help="Run the autonomous polling loop with no MCP transport")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level), stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    _pipeline = _build_pipeline(args.config)

    if args.command == "serve":
        mcp.run(transport=args.transport)
    elif args.command == "watch":
        run_forever(_pipeline, interval_hours=_pipeline.config.plugin_feed.poll_interval_hours)


if __name__ == "__main__":
    main()
