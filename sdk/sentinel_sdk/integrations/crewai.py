"""
CrewAI integration for SentinelOS.

Provides a tool wrapper that enforces SentinelOS governance
on every CrewAI agent tool execution.

Usage:
    from sentinel_sdk.integrations.crewai import SentinelGuardedTool

    guarded_search = SentinelGuardedTool(
        tool=search_tool,
        gateway_url="https://sentinel.company.com",
        api_key=os.environ["SENTINEL_API_KEY"],
    )

    agent = Agent(tools=[guarded_search], ...)
"""

from __future__ import annotations

from typing import Any, List, Optional

from sentinel_sdk.client import GuardDecision, SentinelClient


class SentinelGuardedTool:
    """
    Wraps any CrewAI-compatible tool with SentinelOS governance.
    Before each execution, the tool call is submitted to the Sentinel
    guard for risk evaluation and policy enforcement.
    """

    def __init__(
        self,
        tool: Any,
        gateway_url: str,
        api_key: str,
        data_classification: Optional[List[str]] = None,
    ):
        self._inner_tool = tool
        self._client = SentinelClient(gateway_url=gateway_url, api_key=api_key)
        self._classification = data_classification or []

        # Preserve tool metadata for CrewAI discovery
        self.name = getattr(tool, "name", type(tool).__name__)
        self.description = getattr(tool, "description", "Sentinel-guarded tool")

    def run(self, *args, **kwargs) -> Any:
        """Synchronous execution with Sentinel guard check."""
        # Positional arguments are sent too: the guard evaluates everything the
        # tool will receive, not only what happened to be passed by keyword.
        parameters = {"args": list(args), **kwargs} if args else dict(kwargs)
        decision = self._client.guard_sync(
            tool_name=self.name,
            parameters=parameters,
            data_classification=self._classification,
        )
        self._last_decision = decision

        risk = f"risk={decision.risk_score}"
        if decision.requires_step_up:
            return f"[SENTINEL STEP-UP REQUIRED] Tool '{self.name}' requires human approval ({risk})"

        # Fail closed: a status this SDK does not recognise is not permission.
        if not decision.allowed:
            return f"[SENTINEL DENIED] Tool '{self.name}' blocked: {decision.reason} ({risk})"

        return self._inner_tool.run(*args, **kwargs)

    @property
    def last_decision(self) -> Optional[GuardDecision]:
        return getattr(self, "_last_decision", None)
