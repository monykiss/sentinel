"""
SentinelOS SDK Client — drop-in governance for any AI agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx


class SentinelError(Exception):
    """Raised when the Sentinel gateway returns an unexpected error."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Sentinel error {status_code}: {detail}")


@dataclass
class GuardDecision:
    """Result of a tool execution governance check."""

    status: str  # "allowed", "denied", "step-up-auth"
    risk_score: int
    reason: Optional[str] = None
    capability_token: Optional[str] = None
    advisory_only: bool = False
    explainability_context: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    @property
    def denied(self) -> bool:
        return self.status == "denied"

    @property
    def requires_step_up(self) -> bool:
        return self.status == "step-up-auth"


GUARD_PATH = "/v1/guard/execute-tool"


def _detail(response: httpx.Response, default: str) -> str:
    """Best-effort error detail. A proxy in front of the gateway may answer
    with HTML, so a non-JSON body must not turn into a parse error."""
    try:
        body = response.json()
    except ValueError:
        return default
    if isinstance(body, dict):
        return str(body.get("detail") or default)
    return default


def _guard_payload(
    tool_name: str,
    parameters: Dict[str, Any],
    data_classification: Optional[List[str]],
) -> Dict[str, Any]:
    return {
        "tool_name": tool_name,
        "parameters": parameters,
        "data_classification": data_classification or [],
    }


def _decision_from(response: httpx.Response) -> GuardDecision:
    """Map a guard response to a decision, failing closed.

    Anything that is not an explicit answer from the gateway is raised, never
    defaulted to "allowed": an agent must not read "could not ask" as "yes".
    """
    if response.status_code in (401, 403):
        raise SentinelError(response.status_code, _detail(response, "Unauthorized"))
    if response.status_code == 429:
        raise SentinelError(429, "Rate limit exceeded")
    if response.status_code >= 400:
        raise SentinelError(response.status_code, _detail(response, "Sentinel gateway error"))

    data = response.json()
    return GuardDecision(
        status=data.get("status", "denied"),
        risk_score=data.get("risk_score", 100),
        reason=data.get("reason"),
        capability_token=data.get("capability_token_issued"),
        advisory_only=data.get("advisory_only", False),
        explainability_context=data.get("explainability_context"),
    )


class SentinelClient:
    """
    Client for the SentinelOS governance gateway.

    Async methods share one connection pool. ``guard_sync`` opens a short-lived
    synchronous client per call, so sync framework hooks (LangChain callbacks,
    CrewAI tools) never drive the async pool from a different event loop.

    Args:
        gateway_url: Base URL of the SentinelOS gateway
        api_key: Bearer token for authentication
        timeout: Request timeout in seconds (default 10)
    """

    def __init__(
        self,
        gateway_url: str,
        api_key: str,
        timeout: float = 10.0,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self.gateway_url = gateway_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.gateway_url,
            headers=self._headers,
            timeout=timeout,
        )

    def __repr__(self) -> str:
        # Never render the credential, e.g. in a traceback or a log line.
        return f"SentinelClient(gateway_url={self.gateway_url!r})"

    async def guard(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        data_classification: Optional[List[str]] = None,
    ) -> GuardDecision:
        """
        Submit a tool execution request to the Sentinel guard.
        Returns a GuardDecision indicating whether execution is permitted.
        """
        response = await self._client.post(GUARD_PATH, json=_guard_payload(tool_name, parameters, data_classification))
        return _decision_from(response)

    def guard_sync(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        data_classification: Optional[List[str]] = None,
    ) -> GuardDecision:
        """Synchronous ``guard`` for callers that are not running an event loop."""
        with httpx.Client(base_url=self.gateway_url, headers=self._headers, timeout=self._timeout) as client:
            response = client.post(GUARD_PATH, json=_guard_payload(tool_name, parameters, data_classification))
        return _decision_from(response)

    async def proxy_chat(
        self,
        model: str,
        messages: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Route an LLM chat completion through the Sentinel prompt firewall."""
        response = await self._client.post(
            "/v1/proxy/chat",
            json={"model": model, "messages": messages},
        )

        if response.status_code != 200:
            raise SentinelError(response.status_code, _detail(response, "Proxy error"))

        return response.json()

    async def get_evidence_pack(self, event_id: str) -> Dict[str, Any]:
        """Retrieve a compliance-ready forensic evidence pack."""
        # Quote the id so a crafted value cannot rewrite the request path.
        response = await self._client.get(f"/v1/siem/evidence-pack/{quote(event_id, safe='')}")

        if response.status_code != 200:
            raise SentinelError(response.status_code, _detail(response, "Not found"))

        return response.json()

    async def health(self) -> Dict[str, str]:
        """Check gateway health."""
        response = await self._client.get("/health")
        return response.json()

    async def close(self):
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
