"""MCP client dispatcher — routes agent tool calls through the Splunkology MCP server.

When SPLUNKOLOGY_USE_MCP is enabled, the agent loop dispatches Splunk tools over the
MCP stdio transport (spawning mcp_server.server) instead of calling SplunkClient
directly. Each call runs the full connect/initialize/call/close lifecycle inside one
task to satisfy anyio's cancel-scope contract, and retries the whole lifecycle once on
transport failure. Results map back to the same SocResult shape the direct dispatch
path produces, so nothing downstream changes.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from splunkology.models.soc import SocResult, ToolOutcome

_SERVER_MODULE = "splunkology.mcp_server.server"
_TRUTHY = {"1", "true", "yes", "on"}


def mcp_enabled() -> bool:
    return os.environ.get("SPLUNKOLOGY_USE_MCP", "").strip().lower() in _TRUTHY


def _child_env() -> dict:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass
    return {**os.environ}


def _to_soc_result(name: str, text: str, duration_ms: int) -> SocResult:
    payload = json.loads(text) if text else {}

    if name == "splunk_search":
        return SocResult(
            tool=name,
            outcome=ToolOutcome.OK,
            summary=f"{payload.get('event_count', 0)} events in "
            f"{payload.get('duration_ms', duration_ms)}ms",
            duration_ms=payload.get("duration_ms", duration_ms),
            raw={"events": payload.get("events", []), "job_id": payload.get("job_id")},
        )
    if name == "splunk_indexes":
        indexes = payload if isinstance(payload, list) else payload.get("indexes", [])
        return SocResult(
            tool=name,
            outcome=ToolOutcome.OK,
            summary=f"{len(indexes)} indexes",
            duration_ms=duration_ms,
            raw={"indexes": indexes},
        )
    if name == "splunk_server_info":
        return SocResult(
            tool=name,
            outcome=ToolOutcome.OK,
            summary=f"Splunk {payload.get('version', 'unknown')}",
            duration_ms=duration_ms,
            raw=payload,
        )
    return SocResult(
        tool=name, outcome=ToolOutcome.OK, summary="ok", duration_ms=duration_ms, raw=payload
    )


class MCPDispatcher:
    """Per-call MCP stdio client. No persistent session — each call owns its lifecycle."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def _attempt(self, name: str, args: dict) -> tuple[str, bool]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", _SERVER_MODULE],
            env=_child_env(),
        )
        async with stdio_client(params) as (read, write):  # noqa: SIM117  # noqa: SIM117
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.call_tool(name, arguments=args)
        text = "".join(
            getattr(b, "text", "") for b in resp.content if getattr(b, "type", None) == "text"
        )
        return text, bool(getattr(resp, "isError", False))

    async def call(self, name: str, args: dict) -> SocResult:
        async with self._lock:
            t0 = time.monotonic()
            try:
                text, is_error = await self._attempt(name, args)
            except Exception:
                try:
                    text, is_error = await self._attempt(name, args)
                except Exception as exc:
                    return SocResult(
                        tool=name,
                        outcome=ToolOutcome.FAIL,
                        summary=str(exc),
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        error=str(exc),
                    )
            duration_ms = int((time.monotonic() - t0) * 1000)
            print(f"  \u21aa via MCP server: {name}", file=sys.stderr)
            if is_error:
                return SocResult(
                    tool=name,
                    outcome=ToolOutcome.FAIL,
                    summary=text or "mcp tool error",
                    duration_ms=duration_ms,
                    error=text or "mcp tool error",
                )
            return _to_soc_result(name, text, duration_ms)

    async def aclose(self) -> None:
        return None


dispatcher = MCPDispatcher()
