"""MCP server exposing SENTINEL's governance surface to an AI agent.

What is exposed, and what is not, is the design decision here.

Exposed: the read surface and the *decision* surface. An agent can ask what
SENTINEL knows (posture, coverage, attack paths, findings, incidents) and can
ask whether a tool call would be permitted. /v1/guard/execute-tool is a
decision endpoint — it evaluates a call against policy, risk and the capability
graph and returns allow, step-up-auth or deny. It does not run the tool.

Not exposed: anything that changes a customer's environment or the control
plane's own state. No tenant isolation, no key revocation, no breakglass, no
policy activation, no enforcing remediation. The remediation tool is pinned to
dry_run and cannot be talked into enforce, because "plan the cut" is a question
and "make the cut" is an action that should have a human and an approval flow in
front of it. A governance product whose own controls can be driven by a model
over a chat transport is not a governance product.

Every call goes over HTTP to the gateway with a bearer token — see client.py for
why that matters — so the agent is subject to the same route classification,
rate limits, tenant isolation and audit trail as any other caller.

Run it:

    SENTINEL_MCP_BASE_URL=http://localhost:8000 \
    SENTINEL_MCP_TOKEN=<a token for the tenant> \
    python -m sentinel_mcp
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer

from sentinel_mcp.client import SentinelClient, SentinelClientError

server = MCPServer(
    "sentinel",
    instructions=(
        "SENTINEL is an AI runtime governance control plane. Use check_tool_call "
        "before performing a sensitive action to find out whether policy permits "
        "it. Use the read tools to report posture honestly — including coverage, "
        "which says what SENTINEL has NOT been able to observe. An empty finding "
        "list from an uncovered environment is not an all-clear."
    ),
)

_client = SentinelClient()


def _render(value: Any) -> str:
    return json.dumps(value, indent=2, default=str)


async def _call(method: str, path: str, **kwargs: Any) -> str:
    """Run a gateway call and render either the result or an honest failure.

    A refusal and an outage are reported differently on purpose. An agent told
    only "error" may reasonably retry or proceed; it must be able to tell "you
    are not permitted" from "the control plane could not be reached", and it
    must never read the second as permission.
    """
    try:
        if method == "GET":
            return _render(await _client.get(path, kwargs.get("params")))
        return _render(await _client.post(path, kwargs.get("payload")))
    except SentinelClientError as exc:
        if exc.status_code in (401, 403):
            return _render(
                {
                    "permitted": False,
                    "reason": str(exc),
                    "note": "SENTINEL refused this request. Do not proceed.",
                }
            )
        return _render(
            {
                "error": str(exc),
                "status_code": exc.status_code,
                "note": (
                    "SENTINEL could not answer. This is not permission — treat it as "
                    "unknown and do not proceed with a sensitive action."
                ),
            }
        )


@server.tool(
    name="sentinel_check_tool_call",
    description=(
        "Ask SENTINEL whether an agent may run a tool against data of a given "
        "classification. Returns allow, step-up-auth or deny with the policy and "
        "risk reasoning. This evaluates the call; it does not run it."
    ),
)
async def check_tool_call(
    tool_name: str,
    data_classification: list[str],
    parameters: dict[str, Any] | None = None,
) -> str:
    """Evaluate a proposed tool call against policy, risk and the capability graph.

    data_classification is the sensitivity of the data the call would touch, e.g.
    ["regulated"] or ["internal"]. Privilege is taken from the tenant's signed
    policy pack rather than the tool name, so renaming a tool does not lower its
    risk score.
    """
    return await _call(
        "POST",
        "/v1/guard/execute-tool",
        payload={
            "tool_name": tool_name,
            "parameters": parameters or {},
            "data_classification": data_classification,
        },
    )


@server.tool(
    name="sentinel_coverage",
    description=(
        "What SENTINEL has and has not been able to observe for this tenant. "
        "Read this before reporting that an environment is clean: an uncollected "
        "tenant and a secure one produce the same empty finding list."
    ),
)
async def coverage() -> str:
    """Collection coverage, and which sources contributed."""
    return await _call("GET", "/v1/graph/coverage")


@server.tool(
    name="sentinel_posture",
    description=(
        "Current security posture for the tenant: inventory, datasets by "
        "classification, critical paths discovered and still open, and the "
        "caveats that qualify the headline."
    ),
)
async def posture() -> str:
    """Read-only posture. Runs no discovery cycle."""
    return await _call("GET", "/v1/graph/posture")


@server.tool(
    name="sentinel_attack_paths",
    description=(
        "Routes from a principal to sensitive data — which agents can reach "
        "regulated datasets, and through which capabilities."
    ),
)
async def attack_paths() -> str:
    """Discovered attack paths for the tenant."""
    return await _call("GET", "/v1/graph/paths")


@server.tool(
    name="sentinel_findings",
    description="Open security findings for the tenant, with severity and status.",
)
async def findings(status: str | None = None) -> str:
    """Security findings. Optionally filter by status."""
    return await _call("GET", "/v1/findings", params={"status": status} if status else None)


@server.tool(
    name="sentinel_incidents",
    description="Incidents for the tenant, including regulatory notification clocks.",
)
async def incidents() -> str:
    """Incident register."""
    return await _call("GET", "/v1/incidents")


@server.tool(
    name="sentinel_remediation_plan",
    description=(
        "What SENTINEL would cut to close the critical paths, without cutting "
        "anything. Always a dry run — this tool cannot enforce."
    ),
)
async def remediation_plan() -> str:
    """Plan the minimum cut. Pinned to dry_run.

    mode is not a parameter. Enforcement changes a customer's environment and
    belongs behind a human and an approval flow, not behind a model deciding a
    request body.
    """
    return await _call("POST", "/v1/graph/remediate", payload={"mode": "dry_run"})


def main() -> None:
    """Run over stdio, which is how an MCP client launches this."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
