"""HTTP client for the SENTINEL gateway.

This is deliberately an HTTP client and not an import of the gateway's
internals, and that decision is the whole security argument for this package.

Calling `sentinel_gateway.routers.guard.execute_tool` directly from an MCP
server would be simpler and faster, and it would bypass every control this
gateway has: RouteAccessMiddleware, which enforces the access level each route
declares; the rate limiter and its per-tenant budgets; the tenant resolution
that decides whose graph is consulted; and the audit ledger entry that records
the call happened. An in-process caller inherits none of those, because all of
them live in the request path.

Going over HTTP with a bearer token means an AI agent driving SENTINEL is
subject to exactly the same gates as any other client, is rate limited like any
other client, and appears in the audit trail like any other client. The cost is
a network hop. That is the correct trade for a control plane.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

#: Long enough for a policy evaluation and a graph query, short enough that an
#: assistant does not hang on an unreachable gateway.
DEFAULT_TIMEOUT_SECONDS = 15.0


class SentinelClientError(RuntimeError):
    """A call to the gateway did not succeed.

    Carries the status code so callers can tell "you may not" (403) from
    "SENTINEL is down" (connection error) — which are very different answers to
    give an agent asking whether it may proceed.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class SentinelClient:
    """Talks to a SENTINEL gateway over its public API."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = (base_url or os.environ.get("SENTINEL_MCP_BASE_URL") or "http://localhost:8000").rstrip("/")
        self.token = token or os.environ.get("SENTINEL_MCP_TOKEN") or ""
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(method, url, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            # Unreachable is not the same as refused, and an agent must not read
            # "I could not ask" as "I was told yes".
            raise SentinelClientError(f"SENTINEL unreachable at {self.base_url}: {exc}") from exc

        if response.status_code >= 400:
            detail = _detail(response)
            raise SentinelClientError(
                f"{method} {path} -> {response.status_code}: {detail}",
                status_code=response.status_code,
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise SentinelClientError(f"{method} {path} returned a non-JSON body") from exc

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params or {})

    async def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", path, json=payload or {})


def _detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or body)[:300]
    return str(body)[:300]
