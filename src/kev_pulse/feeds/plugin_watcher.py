"""Plugin Watcher.

Polls Tenable's plugin database (the "List Plugins" API under
developer.tenable.com) for plugins that are new or have been updated since
the last successful cycle, using the `last_updated` query parameter.

This is Tenable's shared plugin corpus, not customer-specific scan data, so
the watcher is backend-agnostic: it runs the same way whether the customer's
scan backend is Tenable Security Center or Tenable Vulnerability Management.

NOTE ON FIELD NAMES: Tenable's plugin API response shape can vary by API
version/tenant. `_normalize_plugin` below accepts a few common key spellings
defensively and should be checked against a live response for your tenant
before relying on it in production -- see developer.tenable.com/reference
for the current schema.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any, Optional

import requests

from ..models import Plugin

logger = logging.getLogger(__name__)


class PluginWatcher:
    def __init__(
        self,
        url: str,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        page_size: int = 1000,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ):
        self.url = url
        self.access_key = access_key
        self.secret_key = secret_key
        self.page_size = page_size
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key};secretKey={self.secret_key}"
        return headers

    def poll(self, since: Optional[str] = None) -> list[Plugin]:
        """Return every plugin created or modified on/after `since`
        (YYYY-MM-DD). If `since` is None, returns today's changes only, to
        avoid an unbounded first pull -- pass an explicit date for backfill.
        """
        since = since or date.today().isoformat()
        plugins: list[Plugin] = []
        page = 1
        while True:
            params = {"last_updated": since, "page": page, "size": self.page_size}
            resp = self.session.get(
                self.url, headers=self._headers(), params=params, timeout=self.timeout
            )
            resp.raise_for_status()
            payload = resp.json()
            raw_items = _extract_items(payload)
            if not raw_items:
                break
            for raw in raw_items:
                try:
                    plugins.append(_normalize_plugin(raw))
                except Exception:  # pragma: no cover - defensive
                    logger.exception("Skipping unparseable plugin record: %r", raw)
            if len(raw_items) < self.page_size:
                break
            page += 1
        return plugins


def _extract_items(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "plugin_details", "plugins", "items"):
            val = payload.get(key)
            if isinstance(val, list):
                return val
            if isinstance(val, dict) and isinstance(val.get("plugin_details"), list):
                return val["plugin_details"]
    return []


def _normalize_plugin(raw: dict) -> Plugin:
    plugin_id = str(raw.get("id") or raw.get("plugin_id") or raw.get("pluginID"))
    name = raw.get("name") or raw.get("plugin_name") or ""
    family = (
        raw.get("family_name")
        or raw.get("family")
        or (raw.get("attributes", {}) or {}).get("plugin_family")
        or ""
    )
    cves = _extract_cves(raw)
    cvss = _first_number(
        raw.get("cvss3_base_score"),
        raw.get("cvss_base_score"),
        (raw.get("attributes", {}) or {}).get("cvss3_base_score"),
    )
    last_updated = (
        raw.get("last_updated")
        or raw.get("plugin_modification_date")
        or raw.get("modification_date")
    )
    return Plugin(
        plugin_id=plugin_id,
        name=name,
        family=family,
        cves=cves,
        cvss3_base_score=cvss,
        last_updated=last_updated,
    )


def _extract_cves(raw: dict) -> list[str]:
    for key in ("cve", "cves", "cve_id"):
        val = raw.get(key)
        if isinstance(val, list):
            return [str(v) for v in val]
        if isinstance(val, str) and val:
            return [val]
    attrs = raw.get("attributes") or {}
    val = attrs.get("cve")
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _first_number(*vals) -> Optional[float]:
    for v in vals:
        if v is None:
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    return None
