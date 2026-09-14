"""KEV-Pulse

An MCP server, deployed at the customer site, that watches Tenable's plugin
release feed and the CISA Known Exploited Vulnerabilities (KEV) catalog,
correlates the two, resolves the customer's own dynamic tags for anything
newly actionable, and (behind guardrails) launches a scoped scan on either
Tenable Security Center or Tenable Vulnerability Management.

See README.md for the full architecture and usage.
"""

__version__ = "0.1.0"
