"""An agent must be able to tell "you may not" from "I could not ask".

Both are non-answers to "may I run this tool", and they call for opposite
behaviour: a refusal is final, an outage is unknown. Collapsing them into one
"error" string invites a model to retry, or worse to proceed because nothing
said no.

So the client keeps the status code and the server renders the two differently,
and neither ever renders as permission.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from sentinel_mcp.client import SentinelClient, SentinelClientError

BASE = "http://sentinel.test"


def _client() -> SentinelClient:
    return SentinelClient(base_url=BASE, token="a-token")


@pytest.mark.asyncio
class TestTheClientPreservesWhatHappened:
    @respx.mock
    async def test_a_successful_call_returns_the_body(self) -> None:
        respx.get(f"{BASE}/v1/findings").mock(return_value=httpx.Response(200, json={"findings": [], "total": 0}))
        assert await _client().get("/v1/findings") == {"findings": [], "total": 0}

    @respx.mock
    async def test_a_refusal_keeps_its_status(self) -> None:
        respx.post(f"{BASE}/v1/guard/execute-tool").mock(
            return_value=httpx.Response(403, json={"detail": "Deny by default."})
        )
        with pytest.raises(SentinelClientError) as caught:
            await _client().post("/v1/guard/execute-tool", {"tool_name": "x"})
        assert caught.value.status_code == 403
        assert "Deny by default" in str(caught.value)

    @respx.mock
    async def test_an_outage_has_no_status(self) -> None:
        """Nothing answered, so there is no answer to report — and the absence
        of a status is how the server tells this apart from a refusal."""
        respx.get(f"{BASE}/v1/graph/posture").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(SentinelClientError) as caught:
            await _client().get("/v1/graph/posture")
        assert caught.value.status_code is None
        assert "unreachable" in str(caught.value).lower()

    @respx.mock
    async def test_the_credential_is_sent(self) -> None:
        route = respx.get(f"{BASE}/v1/findings").mock(return_value=httpx.Response(200, json={}))
        await _client().get("/v1/findings")
        assert route.calls.last.request.headers["Authorization"] == "Bearer a-token"


@pytest.mark.asyncio
class TestTheServerRendersThemDifferently:
    """These need the MCP SDK, which is an optional extra.

    Scoped to this class on purpose. The client tests above exercise the
    refusal/outage distinction with nothing but httpx and must run on every
    matrix; only the tools themselves need `poetry install --extras mcp`. CI's
    "full" job installs all extras, so these do run somewhere — a test that
    skips everywhere is a test that does not exist.
    """

    @pytest.fixture(autouse=True)
    def _requires_sdk(self) -> None:
        pytest.importorskip(
            "mcp",
            reason="MCP SDK is an optional extra: poetry install --extras mcp",
        )

    @staticmethod
    async def _call(name: str, args: dict) -> dict:
        from sentinel_mcp.server import server

        result = await server.call_tool(name, args)
        for item in getattr(result, "content", []) or []:
            if getattr(item, "text", None):
                return json.loads(item.text)
        raise AssertionError("tool returned no text content")

    @respx.mock
    async def test_a_refusal_says_do_not_proceed(self, monkeypatch) -> None:
        from sentinel_mcp import server as server_module

        monkeypatch.setattr(server_module, "_client", _client())
        respx.post(f"{BASE}/v1/guard/execute-tool").mock(
            return_value=httpx.Response(403, json={"detail": "No active policy found."})
        )
        payload = await self._call(
            "sentinel_check_tool_call",
            {"tool_name": "sql_runner", "data_classification": ["regulated"]},
        )
        assert payload["permitted"] is False
        assert "do not proceed" in payload["note"].lower()

    @respx.mock
    async def test_an_outage_is_not_reported_as_permission(self, monkeypatch) -> None:
        """The failure that matters: an unreachable control plane must not read
        as an allow."""
        from sentinel_mcp import server as server_module

        monkeypatch.setattr(server_module, "_client", _client())
        respx.post(f"{BASE}/v1/guard/execute-tool").mock(side_effect=httpx.ConnectError("no route to host"))
        payload = await self._call(
            "sentinel_check_tool_call",
            {"tool_name": "sql_runner", "data_classification": ["regulated"]},
        )
        assert payload.get("permitted") is not True
        assert "not permission" in payload["note"].lower()
        assert "do not proceed" in payload["note"].lower()

    @respx.mock
    async def test_a_successful_read_is_passed_through(self, monkeypatch) -> None:
        from sentinel_mcp import server as server_module

        monkeypatch.setattr(server_module, "_client", _client())
        respx.get(f"{BASE}/v1/graph/coverage").mock(
            return_value=httpx.Response(200, json={"complete": False, "sources": {}})
        )
        payload = await self._call("sentinel_coverage", {})
        assert payload == {"complete": False, "sources": {}}
