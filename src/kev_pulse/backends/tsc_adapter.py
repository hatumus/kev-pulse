"""Tenable Security Center (TSC) backend adapter.

Implements the sequence documented in Tenable's own "Launch a Remediation
Scan" API best-practice guide (docs.tenable.com/security-center):

  1. POST /token                       -- session auth
  2. GET  /rest/pluginFamily/{id}      -- confirm plugin family
  3. POST /rest/policy                 -- create a scan policy scoped to
                                           the matched plugin family (plus
                                           the mandatory Nessus Scan
                                           Information family/plugin)
  4. POST /rest/scan                   -- launch now, targeted at the
                                           asset list(s) resolved from the
                                           customer's existing tags

NOTE: exact filter syntax for /rest/tag and /rest/asset can vary by TSC
version. Confirm field names against your instance's
docs.tenable.com/security-center/api reference before relying on this in
production -- the calls below are written defensively (broad filters,
tolerant parsing) but are illustrative, not a guaranteed-exact contract.
"""
from __future__ import annotations

from typing import Optional

import requests

from ..models import Plugin, ScanPlan, ScanResult
from .base import BackendAdapter

# Every TSC scan policy must include the Nessus Scan Information plugin so
# the scan reports its own metadata correctly -- see Tenable's own guide.
NESSUS_SCAN_INFO_FAMILY_ID = "41"
NESSUS_SCAN_INFO_PLUGIN_ID = "19506"


class TSCAdapter(BackendAdapter):
    name = "sc"

    def __init__(
        self,
        url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()
        self._token: Optional[str] = None

    # -- auth ------------------------------------------------------------

    def authenticate(self) -> None:
        resp = self.session.post(
            f"{self.url}/rest/token",
            json={"username": self.username, "password": self.password},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        self._token = resp.json()["response"]["token"]

    def _headers(self) -> dict:
        if self._token is None:
            self.authenticate()
        return {"X-SecurityCenter": self._token, "Content-Type": "application/json"}

    # -- tag / asset resolution ------------------------------------------

    def resolve_tags_for_plugin(self, plugin_family: str, tag_mapping: dict) -> list[str]:
        candidate_tags: list[str] = []
        for keyword, tags in tag_mapping.items():
            if keyword.lower() in (plugin_family or "").lower():
                candidate_tags.extend(tags)
        # de-dupe, preserve order
        seen = set()
        result = []
        for t in candidate_tags:
            if t not in seen:
                seen.add(t)
                result.append(t)
        return [t for t in result if self._tag_exists(t)]

    def _tag_exists(self, tag_name: str) -> bool:
        resp = self.session.get(
            f"{self.url}/rest/tag",
            headers=self._headers(),
            params={"filterField": "name", "filterValue": tag_name},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if resp.status_code != 200:
            return False
        data = resp.json().get("response", [])
        return len(data) > 0

    def _asset_list_ids_for_tags(self, tags: list[str]) -> list[str]:
        ids: list[str] = []
        for tag in tags:
            resp = self.session.get(
                f"{self.url}/rest/asset",
                headers=self._headers(),
                params={"filterField": "tags", "filterValue": tag},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            resp.raise_for_status()
            for item in resp.json().get("response", {}).get("usable", []):
                ids.append(str(item["id"]))
        return ids

    # -- scan plan / launch ------------------------------------------------

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

    def _resolve_family_id(self, family_name: str) -> str:
        """Plugin families in Tenable.sc are addressed by numeric id, but
        our Plugin records carry the family *name* (e.g. "Web Servers").
        Look it up once via GET /rest/pluginFamily; falls back to treating
        the input as already-an-id if no name match is found."""
        resp = self.session.get(
            f"{self.url}/rest/pluginFamily",
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        for fam in resp.json().get("response", []):
            if fam.get("name", "").lower() == (family_name or "").lower():
                return str(fam["id"])
        return family_name

    def _create_policy(self, plugin_family_id: str, plugin_family_name: str, policy_template_id: str) -> str:
        plugin_family_id = self._resolve_family_id(plugin_family_id)
        payload = {
            "name": f"KEV-Pulse: {plugin_family_name}",
            "context": "scan",
            "families": [
                {"id": plugin_family_id, "plugins": []},
                {"id": NESSUS_SCAN_INFO_FAMILY_ID, "plugins": [NESSUS_SCAN_INFO_PLUGIN_ID]},
            ],
            "policyTemplate": {"id": policy_template_id},
        }
        resp = self.session.post(
            f"{self.url}/rest/policy",
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        return str(resp.json()["response"]["id"])

    def launch_scan(self, plan: ScanPlan) -> ScanResult:
        asset_ids = self._asset_list_ids_for_tags(plan.tags)
        if not asset_ids:
            raise RuntimeError(
                f"No asset lists resolved for tags {plan.tags}; refusing to launch an "
                f"unscoped scan. Confirm the tags exist and contain assets."
            )
        policy_id = self._create_policy(
            plugin_family_id=plan.plugin_family,
            plugin_family_name=plan.plugin_family or plan.plugin_name,
            policy_template_id=plan.policy_template_id,
        )
        payload = {
            "name": f"KEV-Pulse scan: {plan.plugin_name} ({plan.cve_id})",
            "policy": {"id": policy_id},
            "assets": [{"id": aid} for aid in asset_ids],
            "schedule": {"type": "now"},
            "type": "policy",
        }
        resp = self.session.post(
            f"{self.url}/rest/scan",
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        scan_id = str(resp.json()["response"]["id"])
        return ScanResult(scan_id=scan_id, status="launched", backend=self.name)

    def get_scan_status(self, scan_id: str) -> str:
        resp = self.session.get(
            f"{self.url}/rest/scanResult/{scan_id}",
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        resp.raise_for_status()
        return resp.json().get("response", {}).get("status", "unknown")
