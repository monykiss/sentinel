"""
LangChain integration for SentinelOS.

Provides a callback handler that intercepts every tool call
and routes it through the Sentinel guard for approval.

Usage:
    from sentinel_sdk.integrations.langchain import SentinelCallbackHandler

    handler = SentinelCallbackHandler(
        gateway_url="https://sentinel.company.com",
        api_key=os.environ["SENTINEL_API_KEY"],
    )

    agent = initialize_agent(tools, llm, callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sentinel_sdk.client import GuardDecision, SentinelClient

logger = logging.getLogger(__name__)


class SentinelToolGuardError(Exception):
    """Raised when Sentinel denies a tool execution."""

    def __init__(self, decision: GuardDecision):
        self.decision = decision
        super().__init__(
            f"Tool execution denied by SentinelOS: {decision.status} "
            f"(risk={decision.risk_score}, reason={decision.reason})"
        )


class SentinelCallbackHandler:
    """
    LangChain callback handler that enforces SentinelOS governance
    on every tool invocation.

    Compatible with LangChain's BaseCallbackHandler interface.
    """

    def __init__(
        self,
        gateway_url: str,
        api_key: str,
        block_on_deny: bool = True,
        data_classification: Optional[list] = None,
    ):
        self.client = SentinelClient(gateway_url=gateway_url, api_key=api_key)
        self.block_on_deny = block_on_deny
        self.default_classification = data_classification or []
        self._last_decision: Optional[GuardDecision] = None

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Intercept tool execution and check with Sentinel guard."""
        tool_name = serialized.get("name", "unknown_tool")

        # LangChain calls this hook synchronously, sometimes from inside a
        # running event loop. A blocking HTTP call works in both cases and
        # never hands the async connection pool to a second loop.
        decision = self.client.guard_sync(
            tool_name=tool_name,
            parameters={"input": input_str},
            data_classification=self.default_classification,
        )

        self._last_decision = decision

        # step-up-auth needs a human; with no approval flow here, it blocks.
        if self.block_on_deny and not decision.allowed:
            raise SentinelToolGuardError(decision)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        logger.debug("Sentinel Callback: Tool execution completed, output length %s chars.", len(output))

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        logger.error("Sentinel Callback: Tool execution failed with error: %s", error, exc_info=True)

    @property
    def last_decision(self) -> Optional[GuardDecision]:
        return self._last_decision
