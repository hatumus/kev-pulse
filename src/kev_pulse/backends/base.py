"""Abstract backend adapter interface.

Both the Tenable Security Center adapter and the Tenable Vulnerability
Management adapter implement this same interface so the rest of the
pipeline (correlation, guardrails, MCP tools) never has to know which
backend is in play.
"""
from __future__ import annotations

import abc
from typing import Optional

from ..models import Plugin, ScanPlan, ScanResult


class BackendAdapter(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def resolve_tags_for_plugin(self, plugin_family: str, tag_mapping: dict) -> list[str]:
        """Return the customer's existing dynamic tags / asset groups that
        apply to `plugin_family`, using the customer-supplied tag_mapping
        (plugin family keyword -> tag name(s)) confirmed against the
        backend's own tag/asset API.

        This intentionally does NOT invent a new tagging taxonomy or try to
        infer OS/CPE matches automatically -- it reuses tags the customer
        already maintains, per the architecture's "no new taxonomy" design
        note. See the README for how to populate `scan.tag_mapping`.
        """

    @abc.abstractmethod
    def build_scan_plan(
        self, plan_id: str, cve_id: str, plugin: Plugin, tags: list[str], policy_template_id: str
    ) -> ScanPlan:
        """Construct (but do not launch) a scan plan scoped to `tags`."""

    @abc.abstractmethod
    def launch_scan(self, plan: ScanPlan) -> ScanResult:
        """Launch the scan described by `plan`. Mutating; guarded by the
        GuardrailGate before this is ever called."""

    @abc.abstractmethod
    def get_scan_status(self, scan_id: str) -> str:
        """Return the current status string for a previously launched scan."""
