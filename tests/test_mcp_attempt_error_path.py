import asyncio

import pytest

from splunkology.mcp_server.client import MCPDispatcher
from splunkology.models.soc import ToolOutcome


def test_call_tool_raising_yields_fail_not_unbound(monkeypatch):
    """A 400-class error inside _attempt must become a FAIL SocResult, never UnboundLocalError."""

    async def _boom(self, name, args):
        raise RuntimeError("400 Client Error: Bad Request")

    monkeypatch.setattr(MCPDispatcher, "_attempt", _boom)

    async def _inner():
        d = MCPDispatcher()
        return await d.call("splunk_search", {"spl": "| tstats count"})

    res = asyncio.run(_inner())
    assert res.outcome == ToolOutcome.FAIL
    assert "400" in (res.error or "")


def test_call_recovers_on_second_attempt(monkeypatch):
    calls = {"n": 0}

    async def _flaky(self, name, args):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient transport error")
        return '{"event_count": 7, "duration_ms": 12, "events": []}', False

    monkeypatch.setattr(MCPDispatcher, "_attempt", _flaky)

    async def _inner():
        d = MCPDispatcher()
        return await d.call("splunk_search", {"spl": "index=botsv3"})

    res = asyncio.run(_inner())
    assert res.outcome == ToolOutcome.OK
    assert calls["n"] == 2
