"""
SentinelOS Python SDK

Provides a lightweight client for integrating AI agents with SentinelOS
governance gateway. Handles authentication, tool execution approval,
LLM proxy routing, and audit evidence retrieval.

Usage:
    from sentinel_sdk import SentinelClient

    client = SentinelClient(
        gateway_url="https://sentinel.yourcompany.com",
        api_key=os.environ["SENTINEL_API_KEY"],
    )

    # Check if a tool execution is allowed
    decision = await client.guard(
        tool_name="database_query",
        parameters={"query": "SELECT * FROM users"},
        data_classification=["PII"],
    )

    if decision.allowed:
        # Execute the tool
        ...
"""

from sentinel_sdk.client import GuardDecision, SentinelClient, SentinelError

__all__ = ["SentinelClient", "GuardDecision", "SentinelError"]
__version__ = "1.0.0"
