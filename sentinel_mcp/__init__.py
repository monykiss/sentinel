"""An MCP server that lets an AI agent ask SENTINEL what it is allowed to do.

SENTINEL governs AI agents. Exposing it over MCP closes the loop: an agent can
consult the control plane before acting, and a human driving an assistant can
read posture, coverage and findings without leaving their tooling.

The design constraint that matters is in client.py — every tool is an HTTP call
to the gateway carrying a token, never an in-process import. See that module for
why.
"""

from sentinel_mcp.client import SentinelClient, SentinelClientError

__all__ = ["SentinelClient", "SentinelClientError"]
