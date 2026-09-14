"""Guardrail & Approval Gate.

Sits between "we found a plugin/CVE match and resolved some tags" and
"we actually launched a scan." Three independent controls, all
config-driven, all overridable per call for the human-in-the-loop path:

  - dry_run:                 global kill switch; when on, nothing auto-launches.
  - auto_scan_allow_tags:    only these tags may trigger an *automatic* launch.
  - max_launches_per_window: a rate limit so a busy KEV day or a bulk plugin
                              release can't fire off dozens of scans at once.

A match whose tags are not on the allow-list, or that trips the rate limit,
is not silently dropped -- it is recorded as a proposal so a human (or a
supervising agent) can review and launch it explicitly via
`launch_targeted_scan(..., approve=True)`.
"""
from __future__ import annotations

from .config import GuardrailConfig
from .models import GuardrailDecision
from .state import StateStore


class GuardrailGate:
    def __init__(self, config: GuardrailConfig, state: StateStore):
        self.config = config
        self.state = state

    def evaluate(self, tags: list[str], human_approved: bool = False) -> GuardrailDecision:
        """Decide whether a scan matching `tags` may be auto-launched.

        `human_approved=True` represents an explicit approve=True call on
        the launch_targeted_scan MCP tool -- it bypasses the allow-list
        (a human said yes to this specific plan) but NOT the rate limit,
        which protects the backend regardless of who asked.
        """
        if self.state.count_launches_since(self.config.window_hours) >= self.config.max_launches_per_window:
            return GuardrailDecision(
                approved=False,
                reason=(
                    f"rate limit reached: {self.config.max_launches_per_window} launches "
                    f"in the last {self.config.window_hours}h"
                ),
            )

        if self.config.dry_run and not human_approved:
            return GuardrailDecision(
                approved=False,
                reason="dry_run is enabled; scan proposed but not launched",
                dry_run=True,
            )

        if human_approved:
            return GuardrailDecision(approved=True, reason="explicitly approved via MCP tool call")

        allow = set(self.config.auto_scan_allow_tags)
        matched = allow.intersection(tags)
        if matched:
            return GuardrailDecision(
                approved=True, reason=f"tag(s) {sorted(matched)} on auto-scan allow-list"
            )

        return GuardrailDecision(
            approved=False,
            reason=f"none of {tags} are on the auto-scan allow-list; awaiting human approval",
        )
