"""Offline proof: the MCP dispatch path never hangs and always hands the agent a
result, so a tool error (e.g. a 400 from splunk_search) is recovered like the
direct/CLI path instead of stalling the dashboard event loop.

Root cause covered:
- The child's stderr is routed to a real, always-drained fd (/dev/null) so a
  chatty/erroring child can't deadlock on a full, un-drained stderr pipe.
- Every call() outcome — stall, transport error, tool error, malformed payload —
  becomes a recoverable FAIL SocResult within a bounded time.
"""

from __future__ import annotations

import asyncio

import pytest

import splunkology.mcp_server.client as mc
from splunkology.models.soc import ToolOutcome


async def _bounded(coro, *, limit=3.0):
    # Test-side guard: if the fix regressed and call() hangs, fail fast rather
    # than hanging the whole suite.
    return await asyncio.wait_for(coro, timeout=limit)


def test_attempt_routes_child_stderr_to_drained_devnull(monkeypatch):
    # Proves the deadlock fix: stdio_client is invoked with errlog pointed at the
    # process-lifetime /dev/null sink (a real fileno), never the default
    # captured sys.stderr that can fill and block the child.
    captured: dict = {}

    class _FakeCM:
        async def __aenter__(self):
            raise RuntimeError("stop after capturing errlog")

        async def __aexit__(self, *a):
            return False

    def fake_stdio_client(params, errlog=None):
        captured["errlog"] = errlog
        return _FakeCM()

    monkeypatch.setattr(mc, "stdio_client", fake_stdio_client)

    d = mc.MCPDispatcher()
    with pytest.raises(RuntimeError):
        asyncio.run(d._attempt("splunk_search", {"spl": "index=botsv3"}))

    assert captured["errlog"] is mc._DEVNULL_ERRLOG
    # It must be a real, writable fd — not a captured stream that can deadlock.
    assert captured["errlog"].fileno() >= 0


def test_call_converts_a_hang_into_a_fail(monkeypatch):
    # The reported failure: a stalled call. With the bound, it returns FAIL fast.
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "0.2")

    async def hang(name, args):
        await asyncio.sleep(3600)  # cancellable

    d = mc.MCPDispatcher()
    d._attempt = hang  # type: ignore[method-assign]

    result = asyncio.run(_bounded(d.call("splunk_search", {"spl": "match(query)"})))
    assert result.outcome is ToolOutcome.FAIL
    assert "exceeded" in result.summary


def test_call_recovers_from_transport_exception(monkeypatch):
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "5")
    calls = {"n": 0}

    async def boom(name, args):
        calls["n"] += 1
        raise ConnectionError("stdio transport died")

    d = mc.MCPDispatcher()
    d._attempt = boom  # type: ignore[method-assign]

    result = asyncio.run(_bounded(d.call("splunk_search", {"spl": "x"})))
    assert result.outcome is ToolOutcome.FAIL
    assert "stdio transport died" in result.summary
    assert calls["n"] == 2  # one retry of the full lifecycle


def test_call_maps_tool_error_to_fail(monkeypatch):
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "5")

    async def errored(name, args):
        return "400 Client Error: malformed match(query...)", True

    d = mc.MCPDispatcher()
    d._attempt = errored  # type: ignore[method-assign]

    result = asyncio.run(_bounded(d.call("splunk_search", {"spl": "match(query)"})))
    assert result.outcome is ToolOutcome.FAIL
    assert "400 Client Error" in result.summary


def test_call_malformed_payload_becomes_fail_not_exception(monkeypatch):
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "5")

    async def garbage(name, args):
        return "this is not json", False

    d = mc.MCPDispatcher()
    d._attempt = garbage  # type: ignore[method-assign]

    result = asyncio.run(_bounded(d.call("splunk_search", {"spl": "x"})))
    assert result.outcome is ToolOutcome.FAIL
    assert "malformed MCP result" in result.summary


def test_call_success_path_still_returns_ok(monkeypatch):
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "5")

    async def ok(name, args):
        return '{"event_count": 3, "duration_ms": 12, "events": [1, 2, 3]}', False

    d = mc.MCPDispatcher()
    d._attempt = ok  # type: ignore[method-assign]

    result = asyncio.run(_bounded(d.call("splunk_search", {"spl": "index=botsv3"})))
    assert result.outcome is ToolOutcome.OK
    assert "3 events" in result.summary


def test_call_timeout_env_parsing(monkeypatch):
    monkeypatch.delenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", raising=False)
    assert mc._call_timeout_s() == mc._DEFAULT_CALL_TIMEOUT_S
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "bogus")
    assert mc._call_timeout_s() == mc._DEFAULT_CALL_TIMEOUT_S
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "0")
    assert mc._call_timeout_s() == mc._DEFAULT_CALL_TIMEOUT_S
    monkeypatch.setenv("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "12.5")
    assert mc._call_timeout_s() == 12.5
