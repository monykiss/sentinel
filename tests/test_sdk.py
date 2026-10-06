"""The SDK fails closed, keeps its credential to itself, and shows the guard
everything a tool is about to receive."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from sentinel_sdk import SentinelClient, SentinelError
from sentinel_sdk.integrations.crewai import SentinelGuardedTool
from sentinel_sdk.integrations.langchain import SentinelCallbackHandler, SentinelToolGuardError
from sentinel_sdk.integrations.openai import SentinelDeniedError, sentinel_guard_wrapper

BASE = "http://sentinel.test"
GUARD = f"{BASE}/v1/guard/execute-tool"
TOKEN = "dummy-token-for-tests"


def _client() -> SentinelClient:
    return SentinelClient(gateway_url=BASE, api_key=TOKEN)


def _decision(status: str, **extra) -> httpx.Response:
    return httpx.Response(200, json={"status": status, "risk_score": 10, **extra})


class TestClient:
    def test_an_empty_key_is_refused_up_front(self) -> None:
        with pytest.raises(ValueError):
            SentinelClient(gateway_url=BASE, api_key="")

    def test_repr_never_contains_the_key(self) -> None:
        assert TOKEN not in repr(_client())

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_allowed_call_is_allowed_and_carries_the_credential(self) -> None:
        route = respx.post(GUARD).mock(return_value=_decision("allowed"))
        decision = await _client().guard("kb_search", {"q": "refunds"})
        assert decision.allowed
        assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_refusal_raises(self) -> None:
        respx.post(GUARD).mock(return_value=httpx.Response(403, json={"detail": "Deny by default."}))
        with pytest.raises(SentinelError) as caught:
            await _client().guard("sql_runner", {})
        assert caught.value.status_code == 403
        assert "Deny by default" in caught.value.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_non_json_error_page_still_fails_closed(self) -> None:
        """A proxy in front of the gateway may answer with HTML."""
        respx.post(GUARD).mock(return_value=httpx.Response(502, text="<html>Bad Gateway</html>"))
        with pytest.raises(SentinelError) as caught:
            await _client().guard("sql_runner", {})
        assert caught.value.status_code == 502

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_unexpected_client_error_is_not_read_as_a_decision(self) -> None:
        respx.post(GUARD).mock(return_value=httpx.Response(422, json={"detail": "bad body"}))
        with pytest.raises(SentinelError):
            await _client().guard("sql_runner", {})

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_evidence_id_cannot_rewrite_the_path(self) -> None:
        route = respx.get(url__startswith=f"{BASE}/v1/siem/evidence-pack/").mock(
            return_value=httpx.Response(200, json={})
        )
        await _client().get_evidence_pack("../../admin")
        assert route.calls.last.request.url.raw_path.endswith(b"/evidence-pack/..%2F..%2Fadmin")

    @respx.mock
    def test_guard_sync_works_without_an_event_loop(self) -> None:
        respx.post(GUARD).mock(return_value=_decision("denied", reason="policy"))
        decision = _client().guard_sync("refund_issue", {"amount": 5})
        assert decision.denied
        assert decision.reason == "policy"


class TestOpenAIWrapper:
    @pytest.mark.asyncio
    @respx.mock
    async def test_positional_arguments_reach_the_guard(self) -> None:
        """Sending only kwargs would let a positional argument skip policy."""
        route = respx.post(GUARD).mock(return_value=_decision("allowed"))

        def query_db(sql: str, limit: int = 10) -> str:
            return f"ran {sql}"

        tools = sentinel_guard_wrapper({"query_db": query_db}, BASE, TOKEN)
        assert await tools["query_db"]("DROP TABLE users", limit=1) == "ran DROP TABLE users"
        sent = json.loads(route.calls.last.request.content)
        assert sent["parameters"] == {"sql": "DROP TABLE users", "limit": 1}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", ["denied", "step-up-auth"])
    @respx.mock
    async def test_anything_but_allowed_raises_and_the_tool_never_runs(self, status: str) -> None:
        respx.post(GUARD).mock(return_value=_decision(status))
        calls: list[str] = []

        async def refund(amount: int) -> None:
            calls.append("ran")

        tools = sentinel_guard_wrapper({"refund": refund}, BASE, TOKEN)
        with pytest.raises(SentinelDeniedError):
            await tools["refund"](amount=500)
        assert calls == []


class _Tool:
    name = "search"
    description = "searches"

    def __init__(self) -> None:
        self.calls = 0

    def run(self, *args, **kwargs) -> str:
        self.calls += 1
        return "results"


class TestCrewAITool:
    @respx.mock
    def test_a_denial_is_returned_to_the_agent_and_recorded(self) -> None:
        route = respx.post(GUARD).mock(return_value=_decision("denied", reason="no"))
        inner = _Tool()
        tool = SentinelGuardedTool(inner, BASE, TOKEN)
        assert "DENIED" in tool.run("payroll")
        assert inner.calls == 0
        assert tool.last_decision is not None and tool.last_decision.denied
        assert json.loads(route.calls.last.request.content)["parameters"] == {"args": ["payroll"]}

    @respx.mock
    def test_an_unrecognised_status_does_not_run_the_tool(self) -> None:
        respx.post(GUARD).mock(return_value=_decision("maybe"))
        inner = _Tool()
        assert "DENIED" in SentinelGuardedTool(inner, BASE, TOKEN).run(q="x")
        assert inner.calls == 0

    @respx.mock
    def test_repeated_calls_work(self) -> None:
        """The previous version reused an async pool across asyncio.run() loops."""
        respx.post(GUARD).mock(return_value=_decision("allowed"))
        inner = _Tool()
        tool = SentinelGuardedTool(inner, BASE, TOKEN)
        assert [tool.run(q="a"), tool.run(q="b")] == ["results", "results"]
        assert inner.calls == 2


class TestLangChainHandler:
    @respx.mock
    def test_step_up_blocks(self) -> None:
        respx.post(GUARD).mock(return_value=_decision("step-up-auth"))
        handler = SentinelCallbackHandler(BASE, TOKEN)
        with pytest.raises(SentinelToolGuardError):
            handler.on_tool_start({"name": "deploy_migration"}, "up")

    @pytest.mark.asyncio
    @respx.mock
    async def test_it_works_when_called_inside_a_running_loop(self) -> None:
        respx.post(GUARD).mock(return_value=_decision("allowed"))
        handler = SentinelCallbackHandler(BASE, TOKEN)
        handler.on_tool_start({"name": "kb_search"}, "refund policy")
        assert handler.last_decision is not None and handler.last_decision.allowed
