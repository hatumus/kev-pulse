"""Configuration loading.

Reads a YAML file (see config.example.yaml) and resolves any *_env fields
against the process environment, so credentials never have to be written
into the config file itself. Deliberately dependency-light: PyYAML is the
only third-party import.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class ConfigError(RuntimeError):
    pass


@dataclass
class BackendConfig:
    type: str  # "sc" (Security Center) or "tvm"
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
    # Opt-in: when true, `kev-pulse serve` also starts the same autonomous
    # polling loop `kev-pulse watch` runs standalone, as a background thread
    # inside the MCP server process -- so the MCP extension itself checks
    # feeds.plugin_feed.poll_interval_hours and auto-launches per the other
    # guardrails above, with no separate process to manage. Defaults to
    # false so installing this MCP server never silently starts launching
    # scans in the background unless you explicitly ask for it. Only takes
    # effect for `serve`; `watch` always runs the loop regardless of this
    # flag, since running the loop is its entire purpose. When both a
    # primary and secondary backend are configured, the autonomous loop
    # only ever runs against the primary -- never both -- to keep the
    # highest-risk code path (unattended launching) simple.
    autonomous_in_serve: bool = False


@dataclass
class ScanConfig:
    # Keyed by backend name ("tvm" | "sc"). A TVM scan template uuid and a
    # TSC policy template id are different value spaces, so this is always
    # per-backend internally even though config.yaml may write it as a
    # single string for the common single-backend case -- see
    # load_config below.
    policy_template_id: dict[str, str] = field(default_factory=dict)
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
    # Optional second backend (the other of "tvm"/"sc") so a single running
    # server can operate against both -- see backend.secondary in
    # config.example.yaml. None means only `backend` is configured. The
    # autonomous loop never uses this; it always targets `backend`
    # (the primary) only.
    secondary_backend: Optional[BackendConfig] = None


def _resolve_env(d: dict, key: str) -> Optional[str]:
    """Given {"access_key_env": "TIO_ACCESS_KEY"}, return os.environ value.
    Falls back to a literal `key` value (e.g. {"access_key": "..."}) if no
    `{key}_env` is present. Raises if `{key}_env` IS present but that
    environment variable is unset -- an explicit reference to a missing
    variable is a real misconfiguration, not "this field is just unset"."""
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


def _parse_backend_config(b: dict, *, default_type: str = "tvm") -> BackendConfig:
    """Parse one backend block (the `backend:` block or `backend.secondary:`)
    into a BackendConfig. Raises ConfigError if the block's declared type is
    invalid, or if it's missing the credentials that type requires (TVM:
    access_key + secret_key; TSC: username + password) -- callers treat that
    as "this backend isn't configured/available yet", not necessarily fatal
    to the whole server. Shared so primary and secondary parse identically.
    """
    backend_type = b.get("type", default_type)
    if backend_type not in ("sc", "tvm"):
        raise ConfigError(f"backend.type must be 'sc' or 'tvm', got {backend_type!r}")

    auth = b.get("auth", {})
    backend = BackendConfig(
        type=backend_type,
        # url can be a literal (`url: https://...`) or sourced from the
        # environment (`url_env: TSC_URL`) just like the credential fields
        # below -- lets a packaged extension's config UI fill it in via a
        # plain text field without editing YAML.
        url=b.get("url") or _resolve_env(b, "url") or "https://cloud.tenable.com",
        access_key=_resolve_env(auth, "access_key"),
        secret_key=_resolve_env(auth, "secret_key"),
        username=_resolve_env(auth, "username"),
        password=_resolve_env(auth, "password"),
        verify_tls=bool(b.get("verify_tls", True)),
    )
    if backend_type == "tvm" and not (backend.access_key and backend.secret_key):
        raise ConfigError(
            "TVM backend is missing auth.access_key(_env) and/or auth.secret_key(_env)."
        )
    if backend_type == "sc" and not (backend.username and backend.password):
        raise ConfigError(
            "Security Center backend is missing auth.username(_env) and/or auth.password(_env)."
        )
    return backend


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    b = raw.get("backend", {})
    secondary_raw = b.get("secondary")

    # Parse the two backend blocks independently and non-fatally: a
    # customer who only fills in Security Center credentials (leaving
    # backend.type: tvm's credentials blank, as shipped) -- or only TVM's --
    # should get a working server with no YAML editing required, and one
    # incomplete/misconfigured block must never take the other, working one
    # down with it (see the autonomous-loop outage this caused before this
    # was fixed).
    try:
        primary_parsed: Optional[BackendConfig] = _parse_backend_config(b, default_type="tvm")
        primary_err: Optional[str] = None
    except ConfigError as exc:
        primary_parsed = None
        primary_err = str(exc)

    secondary_parsed: Optional[BackendConfig] = None
    secondary_err: Optional[str] = None
    if secondary_raw:
        try:
            secondary_parsed = _parse_backend_config(secondary_raw, default_type="sc")
        except ConfigError as exc:
            secondary_err = str(exc)
        else:
            if primary_parsed is not None and secondary_parsed.type == primary_parsed.type:
                logger.warning(
                    "backend.secondary.type (%r) is the same as backend.type (%r) -- "
                    "secondary is meant to add the OTHER backend; ignoring backend.secondary.",
                    secondary_parsed.type,
                    primary_parsed.type,
                )
                secondary_parsed = None

    available: dict[str, BackendConfig] = {}
    if primary_parsed is not None:
        available[primary_parsed.type] = primary_parsed
    if secondary_parsed is not None:
        available[secondary_parsed.type] = secondary_parsed

    if not available:
        raise ConfigError(
            "No usable Tenable backend is configured -- fill in credentials for at least "
            "one of TVM or Security Center.\n"
            f"  backend ({b.get('type', 'tvm')}): {primary_err or 'not configured'}\n"
            f"  backend.secondary "
            f"({secondary_raw.get('type', 'sc') if secondary_raw else 'not configured'}): "
            f"{secondary_err or ('not configured' if not secondary_raw else 'ok')}"
        )

    # Decide which available backend is PRIMARY (used by the autonomous
    # polling loop, and by every tool call that omits an explicit `backend`
    # argument):
    #  1. KEVPULSE_BACKEND_TYPE env var, if set to a real value -- lets the
    #     packaged extension's "Primary backend" picker decide without
    #     touching YAML.
    #  2. Otherwise, if only ONE backend has usable credentials, use it --
    #     this is what makes an SC-only (or TVM-only) install just work,
    #     with no picker and no YAML edits.
    #  3. Otherwise (both configured, no override): keep the original
    #     convention -- whichever backend.type says (tvm by default).
    #
    # NOTE: when the packaged extension's "Primary backend" user_config
    # field is left blank, Claude Desktop does NOT substitute the env var
    # with an empty string -- it passes through the literal, unsubstituted
    # template text (e.g. "${user_config.primary_backend}") as-is. That is
    # indistinguishable here from "the user typed something we don't
    # recognize", so *any* value that isn't exactly "tvm" or "sc" is
    # treated as "no override given" (logged, not fatal) rather than
    # crashing the whole server -- an unset optional field must never take
    # down an otherwise-working install.
    raw_override = os.environ.get("KEVPULSE_BACKEND_TYPE")
    override = (raw_override or "").strip().lower()
    if override and override not in ("tvm", "sc"):
        logger.warning(
            "KEVPULSE_BACKEND_TYPE=%r is not 'tvm' or 'sc' (this is expected/harmless if you "
            "left the extension's \"Primary backend\" field blank -- Claude Desktop passes "
            "through the unsubstituted template text in that case) -- ignoring it and "
            "auto-detecting the primary backend instead.",
            raw_override,
        )
        override = ""
    if override:
        if override not in available:
            reason = primary_err if override == b.get("type", "tvm") else secondary_err
            raise ConfigError(
                f"KEVPULSE_BACKEND_TYPE={override!r} but that backend has no usable "
                f"credentials configured ({reason})."
            )
        primary_type = override
    elif len(available) == 1:
        (primary_type,) = available.keys()
    else:
        default_primary_type = b.get("type", "tvm")
        primary_type = default_primary_type if default_primary_type in available else next(iter(available))

    backend = available.pop(primary_type)
    secondary_backend = next(iter(available.values()), None)

    # The plugin feed is always a TVM-style API-key endpoint (Tenable's
    # shared plugin corpus), regardless of which backend the customer
    # actually scans through -- see feeds/plugin_watcher.py. Fall back to
    # whichever configured backend (primary or secondary) is TVM-typed,
    # not blindly to `backend`, since `backend` may be TSC-typed (and so
    # have no access_key/secret_key at all) while a TVM secondary does.
    _tvm_like = None
    if backend.type == "tvm":
        _tvm_like = backend
    elif secondary_backend is not None and secondary_backend.type == "tvm":
        _tvm_like = secondary_backend

    f = raw.get("feeds", {})
    pf = f.get("plugin_feed", {})
    plugin_feed = PluginFeedConfig(
        url=pf.get("url", "https://cloud.tenable.com/plugins/plugin"),
        access_key=_resolve_env(pf.get("auth", {}), "access_key")
        or (_tvm_like.access_key if _tvm_like else None),
        secret_key=_resolve_env(pf.get("auth", {}), "secret_key")
        or (_tvm_like.secret_key if _tvm_like else None),
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
        autonomous_in_serve=bool(g.get("autonomous_in_serve", False)),
    )

    s = raw.get("scan", {})
    raw_policy_template_id = s.get("policy_template_id", "1")
    if isinstance(raw_policy_template_id, dict):
        policy_template_id = {k: str(v) for k, v in raw_policy_template_id.items()}
    else:
        # Backward-compatible single-value form. Fine when only one
        # backend is configured; if a secondary is ALSO configured this is
        # very likely wrong for one of the two (a TVM scan template uuid
        # and a TSC policy template id are different value spaces), so
        # require the explicit per-backend dict form in that case instead
        # of silently reusing one id for both.
        if secondary_backend is not None:
            raise ConfigError(
                "Both backend and backend.secondary are configured, but scan."
                "policy_template_id is a single value. A TVM scan template uuid and a "
                "TSC policy template id are different things -- set scan."
                "policy_template_id as a mapping instead, e.g.:\n"
                "  policy_template_id:\n"
                "    tvm: \"<tvm scan template uuid>\"\n"
                "    sc: \"<tsc policy template id>\""
            )
        policy_template_id = {backend.type: str(raw_policy_template_id)}
    scan = ScanConfig(
        policy_template_id=policy_template_id,
        name_pattern=s.get("name_pattern", "KEV-Pulse: {plugin_family} ({cve})"),
        tag_mapping=dict(s.get("tag_mapping", {})),
    )

    return Config(
        backend=backend,
        plugin_feed=plugin_feed,
        kev_feed=kev_feed,
        thresholds=thresholds,
        guardrails=guardrails,
        scan=scan,
        state_db_path=raw.get("state_db_path", "kev_pulse.db"),
        secondary_backend=secondary_backend,
    )
