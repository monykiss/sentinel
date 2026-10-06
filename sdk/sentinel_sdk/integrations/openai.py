"""
OpenAI Assistants / Function Calling integration for SentinelOS.

Wraps OpenAI function calls so that every tool_call is checked
against the Sentinel guard before execution.

Usage:
    from sentinel_sdk.integrations.openai import sentinel_guard_wrapper

    # Wrap your tool functions
    guarded_tools = sentinel_guard_wrapper(
        tools={"get_weather": get_weather_fn, "query_db": query_db_fn},
        gateway_url="https://sentinel.company.com",
        api_key=os.environ["SENTINEL_API_KEY"],
    )

    # Use guarded_tools in your function-calling loop
    result = await guarded_tools["get_weather"](location="NYC")
"""

from __future__ import annotations

import asyncio
import inspect
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from sentinel_sdk.client import GuardDecision, SentinelClient


class SentinelDeniedError(Exception):
    def __init__(self, tool_name: str, decision: GuardDecision):
        self.tool_name = tool_name
        self.decision = decision
        super().__init__(f"SentinelOS denied execution of '{tool_name}': {decision.reason}")


def _bound_arguments(fn: Callable, args: tuple, kwargs: dict) -> Dict[str, Any]:
    """Every argument the tool will receive, by parameter name.

    The guard must evaluate what the tool is actually called with. Sending only
    kwargs would let a positional argument reach the tool without the policy
    ever seeing it.
    """
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except (TypeError, ValueError):
        # Unbindable call or no introspectable signature: still show the guard
        # everything, rather than nothing.
        return {"args": list(args), **kwargs}
    return dict(bound.arguments)


def sentinel_guard_wrapper(
    tools: Dict[str, Callable],
    gateway_url: str,
    api_key: str,
    data_classification: Optional[List[str]] = None,
) -> Dict[str, Callable]:
    """
    Wraps a dictionary of tool functions with Sentinel governance.
    Each call is checked against the guard before execution; a denial or a
    step-up requirement raises instead of running the tool.
    """
    client = SentinelClient(gateway_url=gateway_url, api_key=api_key)
    classification = data_classification or []

    wrapped: Dict[str, Callable] = {}
    for name, fn in tools.items():

        @wraps(fn)
        async def guarded_fn(*args, _tool_name=name, _fn=fn, **kwargs):
            decision = await client.guard(
                tool_name=_tool_name,
                parameters=_bound_arguments(_fn, args, kwargs),
                data_classification=classification,
            )

            if not decision.allowed:
                raise SentinelDeniedError(_tool_name, decision)

            if asyncio.iscoroutinefunction(_fn):
                return await _fn(*args, **kwargs)
            return _fn(*args, **kwargs)

        wrapped[name] = guarded_fn

    return wrapped
