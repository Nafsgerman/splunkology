"""MCP routing: SPLUNKOLOGY_USE_MCP gates _dispatch_tool onto the MCP dispatcher."""

import asyncio

import splunkology.agent.loop_v2 as loop
from splunkology.models.soc import SocResult, ToolOutcome


def test_dispatch_routes_through_mcp_when_enabled(monkeypatch):
    seen = {}

    async def fake_call(name, args):
        seen["name"] = name
        seen["args"] = args
        return SocResult(tool=name, outcome=ToolOutcome.OK, summary="routed", duration_ms=1, raw={})

    monkeypatch.setenv("SPLUNKOLOGY_USE_MCP", "1")
    monkeypatch.setattr(loop._mcp_dispatcher, "call", fake_call)

    result = asyncio.run(loop._dispatch_tool("splunk_search", {"spl": "index=botsv3"}))

    assert seen["name"] == "splunk_search"
    assert result.summary == "routed"
    assert result.outcome is ToolOutcome.OK


def test_dispatch_uses_direct_path_when_disabled(monkeypatch):
    touched = {"mcp": False}

    async def fake_call(name, args):
        touched["mcp"] = True
        return SocResult(tool=name, outcome=ToolOutcome.OK, summary="x", duration_ms=1, raw={})

    monkeypatch.delenv("SPLUNKOLOGY_USE_MCP", raising=False)
    monkeypatch.setattr(loop._mcp_dispatcher, "call", fake_call)
    monkeypatch.setattr(loop, "SplunkClient", lambda *a, **k: object())

    result = asyncio.run(loop._dispatch_tool("does_not_exist", {}))

    assert touched["mcp"] is False
    assert result.outcome is ToolOutcome.FAIL
