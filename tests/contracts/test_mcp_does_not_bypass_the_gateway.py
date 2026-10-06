"""INVARIANT: the MCP server is a client of SENTINEL, not a way around it.

sentinel_mcp exposes SENTINEL's governance surface to an AI agent. The tempting
implementation is to import the routers and call them — simpler, faster, no
network hop.

It would also bypass every control in the request path: RouteAccessMiddleware,
which enforces the level each route declares; the rate limiter and its
per-tenant budgets; the tenant resolution that decides whose graph is consulted;
and the audit ledger entry recording that the call happened. An in-process
caller inherits none of them, because all of them are middleware.

An MCP server holding a private door into the same application would undo all
of them quietly, and "an AI agent can drive the control plane without appearing
in its audit trail" is the last thing a governance product should ship.

So this asserts the boundary structurally rather than trusting a convention.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "sentinel_mcp"

#: The MCP package may import these. Anything reaching into the running
#: application is the thing this contract exists to prevent.
ALLOWED_FIRST_PARTY = {"sentinel_mcp"}


def _modules() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_package_exists() -> None:
    assert PACKAGE.is_dir(), "sentinel_mcp is missing; this contract has nothing to guard"
    assert _modules(), "sentinel_mcp contains no modules"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_no_module_imports_the_gateway(path: Path) -> None:
    """Importing the application is how the middleware stack gets bypassed."""
    forbidden = {
        root for root in _imported_roots(path) if root.startswith("sentinel_") and root not in ALLOWED_FIRST_PARTY
    } | ({"security"} & _imported_roots(path))
    assert not forbidden, (
        f"{path.name} imports {sorted(forbidden)}. The MCP server must reach "
        "SENTINEL over HTTP so that route classification, rate limiting, tenant "
        "isolation and the audit ledger all still apply to it."
    )


def test_it_reaches_the_gateway_over_http() -> None:
    """The positive half: something must actually be making requests."""
    source = (PACKAGE / "client.py").read_text()
    assert "httpx" in source
    assert "Authorization" in source, "calls must carry a credential like any other client"


class TestToolsExposeNoDestructiveControl:
    """A model may ask SENTINEL questions and ask it for a decision. It may not
    isolate a tenant, revoke keys, activate policy or enforce a remediation.

    Asserted as an allowlist: a new endpoint fails this test until someone
    decides, here and in review, that a model should be able to reach it.
    """

    #: Read endpoints, the decision endpoint, and the dry-run remediation planner.
    ALLOWED_PATHS = {
        "/v1/guard/execute-tool",
        "/v1/graph/coverage",
        "/v1/graph/posture",
        "/v1/graph/paths",
        "/v1/graph/remediate",
        "/v1/findings",
        "/v1/incidents",
    }

    @staticmethod
    def _paths_in_server() -> set[str]:
        tree = ast.parse((PACKAGE / "server.py").read_text())
        return {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("/v1/")
        }

    def test_every_gateway_path_is_on_the_allowlist(self) -> None:
        reached = self._paths_in_server()
        assert reached, "found no gateway paths; this contract has nothing to check"
        unexpected = reached - self.ALLOWED_PATHS
        assert not unexpected, f"MCP tools reach endpoints outside the allowlist: {sorted(unexpected)}"

    def test_remediation_cannot_be_talked_into_enforcing(self) -> None:
        """mode is pinned to dry_run and is not a tool parameter, so no prompt
        can turn 'plan the cut' into 'make the cut'."""
        source = (PACKAGE / "server.py").read_text()
        assert '"mode": "dry_run"' in source
        assert '"mode": "enforce"' not in source
        assert "async def remediation_plan() -> str:" in source, (
            "remediation_plan takes no arguments; adding one would let a caller supply the mode"
        )
