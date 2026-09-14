"""Configuration loading.

Reads a YAML file (see config.example.yaml) and resolves any *_env fields
against the process environment, so credentials never have to be written
into the config file itself. Deliberately dependency-light: PyYAML is the
only third-party import.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml


class ConfigError(RuntimeError):
    pass


@dataclass
class BackendConfig:
    type: str  # "tsc" or "tvm"
    url: str
    # TVM
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    # TSC
    username: Optional[str] = None
    password: Optional[str] = None
    verify_tls: bool = True


@dataclass
class PluginFeedConfig:
    url: str = "https://cloud.tenable.com/plugins/plugin"
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    poll_interval_hours: float = 6.0
    page_size: int = 1000


@dataclass
class KevFeedConfig:
    url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    poll_interval_hours: float = 4.0


@dataclass
class ThresholdConfig:
    min_cvss: float = 7.0
    min_epss: Optional[float] = None


@dataclass
class GuardrailConfig:
    dry_run: bool = True
    auto_scan_allow_tags: list[str] = field(default_factory=list)
    max_launches_per_window: int = 5
    window_hours: float = 24.0


@dataclass
class ScanConfig:
    policy_template_id: str = "1"
    name_pattern: str = "KEV-Pulse: {plugin_family} ({cve})"
    tag_mapping: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Config:
    backend: BackendConfig
    plugin_feed: PluginFeedConfig
    kev_feed: KevFeedConfig
    thresholds: ThresholdConfig
    guardrails: GuardrailConfig
    scan: ScanConfig
    state_db_path: str = "kev_pulse.db"


def _resolve_env(d: dict, key: str) -> Optional[str]:
    """Given {"access_key_env": "TIO_ACCESS_KEY"}, return os.environ value."""
    env_key = d.get(f"{key}_env")
    if env_key:
        val = os.environ.get(env_key)
        if not val:
            raise ConfigError(
                f"Config references environment variable '{env_key}' for '{key}', "
                f"but it is not set."
            )
        return val
    return d.get(key)


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    b = raw.get("backend", {})
    backend = BackendConfig(
        type=b.get("type", "tvm"),
        url=b.get("url", "https://cloud.tenable.com"),
        access_key=_resolve_env(b.get("auth", {}), "access_key"),
        secret_key=_resolve_env(b.get("auth", {}), "secret_key"),
        username=_resolve_env(b.get("auth", {}), "username"),
        password=_resolve_env(b.get("auth", {}), "password"),
        verify_tls=bool(b.get("verify_tls", True)),
    )

    f = raw.get("feeds", {})
    pf = f.get("plugin_feed", {})
    plugin_feed = PluginFeedConfig(
        url=pf.get("url", "https://cloud.tenable.com/plugins/plugin"),
        access_key=_resolve_env(pf.get("auth", {}), "access_key") or backend.access_key,
        secret_key=_resolve_env(pf.get("auth", {}), "secret_key") or backend.secret_key,
        poll_interval_hours=float(pf.get("poll_interval_hours", 6.0)),
        page_size=int(pf.get("page_size", 1000)),
    )
    kf = f.get("kev_feed", {})
    kev_feed = KevFeedConfig(
        url=kf.get(
            "url",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        poll_interval_hours=float(kf.get("poll_interval_hours", 4.0)),
    )
    th = f.get("thresholds", {})
    thresholds = ThresholdConfig(
        min_cvss=float(th.get("min_cvss", 7.0)),
        min_epss=th.get("min_epss"),
    )

    g = raw.get("guardrails", {})
    guardrails = GuardrailConfig(
        dry_run=bool(g.get("dry_run", True)),
        auto_scan_allow_tags=list(g.get("auto_scan_allow_tags", [])),
        max_launches_per_window=int(g.get("max_launches_per_window", 5)),
        window_hours=float(g.get("window_hours", 24.0)),
    )

    s = raw.get("scan", {})
    scan = ScanConfig(
        policy_template_id=str(s.get("policy_template_id", "1")),
        name_pattern=s.get("name_pattern", "KEV-Pulse: {plugin_family} ({cve})"),
        tag_mapping=dict(s.get("tag_mapping", {})),
    )

    if backend.type not in ("tsc", "tvm"):
        raise ConfigError(f"backend.type must be 'tsc' or 'tvm', got {backend.type!r}")

    return Config(
        backend=backend,
        plugin_feed=plugin_feed,
        kev_feed=kev_feed,
        thresholds=thresholds,
        guardrails=guardrails,
        scan=scan,
        state_db_path=raw.get("state_db_path", "kev_pulse.db"),
    )
