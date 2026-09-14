"""Tenable Vulnerability Management (TVM / tenable.io) backend adapter.

Uses API-key authentication (X-ApiKeys header) and TVM's native tag-based
scan targeting, per developer.tenable.com's "Manage Scans" guidance:

  1. resolve the customer's existing tag(s) to tag UUIDs,
  2. create/update a scan whose target is that tag set (reusing an existing
     scan template rather than a full discovery scan),
  3. launch it immediately,
  4. poll "get latest scan status" rather than "get scan details" when
     checking on many scans, per Tenable's own guidance.

NOTE: as with the TSC adapter, exact endpoint paths/payload field names can
shift between API versions. Confirm against developer.tenable.com/reference
for your tenant before production use -- this is a reference
implementation, not a guaranteed-exact contract.
"""
from __future__ import annotations

from typing import Optional

import requests

from ..models import Plugin, ScanPlan, ScanResult
from .base import BackendAdapter


class TVMAdapter(BackendAdapter):
    name = "tvm"

    def __init__(
        self,
        url: str,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.url = url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self) -> dict:
        return {
            "X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # -- tag resolution ----------------------------------------------------

    def resolve_tags_for_plugin(self, plugin_family: str, tag_mapping: dict) -> list[str]:
        candidate_tags: list[str] = []
        for keyword, tags in tag_mapping.items():
            if keyword.lower() in (plugin_family or "").lower():
                candidate_tags.extend(tags)
        seen = set()
        result = []
        for t in candidate_tags:
            if t not in seen:
                seen.add(t)
                result.append(t)
        return [t for t in result if self._tag_value_uuid(t) is not None]

    def _tag_value_uuid(self, tag_value: str) -> Optional[str]:
        resp = self.session.get(
            f"{self.url}/tags/values",
            headers=self._headers(),
            params={"f": f"value:eq:{tag_value}"},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if resp.status_code != 200:
            return None
        values = resp.json().get("values", [])
        return values[0]["uuid"] if values else None

    def _resolve_tag_uuids(self, tags: list[str]) -> list[str]:
        uuids = []
        for tag in tags:
            uuid = self._tag_value_uuid(tag)
            if uuid:
                uuids.append(uuid)
        return uuids

    # -- scan plan / launch --------------------------------------------------

    def build_scan_plan(
        self, plan_id: str, cve_id: str, plugin: Plugin, tags: list[str], policy_template_id: str
    ) -> ScanPlan:
        return ScanPlan(
            plan_id=plan_id,
            cve_id=cve_id,
            plugin_id=plugin.plugin_id,
            plugin_name=plugin.name,
            plugin_family=plugin.family,
            tags=tags,
            backend=self.name,
            policy_template_id=policy_template_id,
        )

    def launch_scan(self, plan: ScanPlan) -> ScanResult:
        tag_uuids = self._resolve_tag_uuids(plan.tags)
        if not tag_uuids:
            raise RuntimeError(
                f"No tag UUIDs resolved for tags {plan.tags}; refusing to launch an "
                f"unscoped scan."
            )
        create_payload = {
            "uuid": plan.policy_template_id,  # an existing scan template uuid, reused
            "settings": {
                "name": f"KEV-Pulse scan: {plan.plugin_name} ({plan.cve_id})",
                "enabled": False,
                "launch": "ON_DEMAND",
                "tag_targets": tag_uuids,
            },
        }
        resp = self.session.post(
            f"{self.url}/scans",
            headers=self._headers(),
            json=create_payload,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        scan_id = str(resp.json()["scan"]["id"])

        launch_resp = self.session.post(
            f"{self.url}/scans/{scan_id}/launch",
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        launch_resp.raise_for_status()
        return ScanResult(scan_id=scan_id, status="launched", backend=self.name)

    def get_scan_status(self, scan_id: str) -> str:
        resp = self.session.get(
            f"{self.url}/scans/{scan_id}/latest-status",
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        return resp.json().get("status", "unknown")
