"""Plain data models shared across the watchers, correlation engine,
guardrail gate, and backend adapters.

Kept as dataclasses (no pydantic dependency required) so the core logic has
zero hard dependencies beyond the standard library; the MCP server layer is
free to wrap these in pydantic models for tool schemas if desired.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Plugin:
    """A single Tenable plugin record, normalized from either the public
    plugin feed or a backend-specific plugin listing."""

    plugin_id: str
    name: str
    family: str
    cves: list[str] = field(default_factory=list)
    cvss3_base_score: Optional[float] = None
    last_updated: Optional[str] = None  # ISO date, YYYY-MM-DD


@dataclass
class KevEntry:
    """A single row from the CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str  # YYYY-MM-DD as published by CISA
    required_action: str = ""
    due_date: str = ""


@dataclass
class CorrelationMatch:
    """One actionable (plugin, CVE) pair produced by the correlation engine."""

    cve_id: str
    plugin_id: str
    plugin_name: str
    plugin_family: str
    reason: str  # "plugin_new_cve_already_kev" | "kev_new_plugin_already_exists"
    cvss3_base_score: Optional[float] = None
    epss: Optional[float] = None


@dataclass
class ScanPlan:
    """A proposed (not yet launched) scan, produced by propose_scan and
    consumed by launch_targeted_scan once approved."""

    plan_id: str
    cve_id: str
    plugin_id: str
    plugin_name: str
    plugin_family: str
    tags: list[str]
    backend: str  # "sc" | "tvm"
    policy_template_id: str
    created_at: str = field(default_factory=utcnow_iso)


@dataclass
class ScanResult:
    scan_id: str
    status: str
    backend: str


@dataclass
class GuardrailDecision:
    approved: bool
    reason: str
    dry_run: bool = False
