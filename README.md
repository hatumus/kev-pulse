# KEV-Pulse

An MCP (Model Context Protocol) server, deployed at the customer site, that
closes the loop between Tenable's plugin releases and real-world exploitation:

1. **Watches** Tenable's plugin feed for new/updated plugins, and the CISA
   Known Exploited Vulnerabilities (KEV) catalog for newly confirmed
   exploited CVEs.
2. **Correlates** the two — a (plugin, CVE) pair is actionable the moment a
   detection plugin exists *and* the CVE is confirmed exploited in the wild,
   regardless of which one showed up first.
3. **Resolves** which of the customer's *existing* dynamic tags are affected,
   via a configurable plugin-family → tag mapping.
4. **Proposes or launches** a scan scoped to exactly those tagged assets, on
   either Tenable Security Center (TSC) or Tenable Vulnerability Management
   (TVM) — never a blind full-network rescan.

Every step is exposed as an MCP tool, so the same pipeline can run on an
autonomous schedule, be driven on demand by a SOC analyst's AI assistant, or
be wired into a larger multi-agent playbook.

Full architecture write-up, sequence diagrams, and the Cyber Exchange
submission plan: see `Tenable_KEV-Pulse_MCP_Architecture.docx` in this
repo (or the project's design doc).

## Why this exists

Neither TSC nor TVM will start a scan on its own just because a new plugin
shipped or a CVE became a known-exploited entry. Dynamic tagging lets a
customer describe *what matters*; this server is the missing piece that
turns "what matters" plus "what just became urgent" directly into a scoped
scan, with a human able to see or override every decision.

## Project layout

```
src/kev_pulse/
  models.py           dataclasses shared across the pipeline
  config.py            YAML config loader, env-var credential resolution
  state.py             SQLite state store: cursors, KEV/plugin index, audit log
  feeds/
    plugin_watcher.py  polls Tenable's plugin feed
    kev_watcher.py      polls the CISA KEV JSON catalog
  correlation.py       matches plugins <-> KEV entries in either order
  guardrails.py        dry-run / allow-list / rate-limit gate
  backends/
    base.py            adapter interface
    tsc_adapter.py      Tenable Security Center implementation
    tvm_adapter.py      Tenable Vulnerability Management implementation
  scheduler.py         wires it all together; the autonomous polling loop
  server.py            MCP tool/resource definitions (FastMCP)
tests/                 unit tests (stdlib unittest + unittest.mock; no live API calls)
config.example.yaml    copy to config.yaml and edit
.env.example           copy to .env and fill in credentials
docker/Dockerfile
```

## Quick start

```bash
pip install -e .
cp config.example.yaml config.yaml   # edit backend type, tag_mapping, guardrails
cp .env.example .env                  # fill in TIO_ACCESS_KEY / TIO_SECRET_KEY (or TSC creds)
export $(grep -v '^#' .env | xargs)

# Run as an MCP server over stdio (for a local MCP client, e.g. Claude Desktop):
kev-pulse --config config.yaml serve

# Or as a remote server for multi-agent orchestration:
kev-pulse --config config.yaml serve --transport streamable-http

# Or skip MCP entirely and just run the autonomous polling loop:
kev-pulse --config config.yaml watch
```

Run the tests (no network access or credentials required — everything is
mocked):

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
# or, with zero extra dependencies:
python -m unittest discover -s tests -v
```

## MCP tools exposed

| Tool | Mutates the backend? | Purpose |
|---|---|---|
| `list_new_plugins(since)` | No | Plugins added/updated since a date or the saved cursor |
| `list_kev_deltas()` | No | CVEs in KEV this server hasn't recorded yet |
| `correlate_exploited_plugins(min_cvss, min_epss)` | No | The current actionable (plugin, CVE) set |
| `resolve_affected_tags(plugin_family)` | No | Which existing dynamic tags a plugin family maps to |
| `propose_scan(cve_id, plugin_id, ...)` | No (local plan only) | Build a scan plan and get back a `scan_plan_id` |
| `launch_targeted_scan(scan_plan_id, approve)` | **Yes** | The only tool that launches a real scan; gated by dry-run/allow-list/rate-limit unless `approve=true` |
| `get_scan_status(scan_id)` | No | Poll a launched scan's status |

Resource: `audit://trigger-history` — full history of every proposed,
launched, rejected, and dry-run event.

## Guardrails (see `guardrails.py`)

- **`dry_run`** — global switch; while on, nothing auto-launches, everything
  becomes a logged proposal. Start here.
- **`auto_scan_allow_tags`** — only scans scoped to these tags may launch
  automatically; anything else waits for a human (or supervising agent) to
  call `launch_targeted_scan(..., approve=true)`.
- **`max_launches_per_window`** — a hard cap that applies even to
  human-approved launches, so a busy KEV day can't trigger a scan storm.

Every decision — approved, rejected, or dry-run — is written to the audit
log with the triggering CVE/plugin and resolved tags, so `audit://trigger-history`
always answers "why did (or didn't) this scan run."

## Notes on accuracy of the included API calls

The TSC and TVM adapters (`backends/tsc_adapter.py`, `backends/tvm_adapter.py`)
follow the documented sequences on `docs.tenable.com` and `developer.tenable.com`
at the time of writing, but Tenable's exact field names can shift between API
versions and tenant configurations. Confirm against your tenant's live API
reference before production use — this is a working reference
implementation, not a guaranteed-exact contract with either API.

## License

MIT — see `LICENSE`.
