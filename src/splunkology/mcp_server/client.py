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

# Child stderr MUST go to a real, always-drained fd. mcp's stdio_client spawns
# the server with `stderr=errlog` but starts NO reader task for the child's
# stderr. Under the CLI, errlog defaults to sys.stderr (the terminal's real fd),
# so the child writes straight through and never blocks. Under uvicorn/the
# dashboard, sys.stderr is a captured stream, so the child's stderr lands on an
# un-drained pipe: a tool error (e.g. a 400 dumps a urllib3 warning + a full
# requests traceback from the unguarded server handler) fills the ~64KB pipe
# buffer, the child blocks mid-write, and `call_tool` hangs forever. Routing the
# child's stderr to /dev/null (a real fileno the child writes to directly) makes
# that deadlock impossible. Tool errors are still surfaced to the agent as FAIL
# SocResults below, so discarding child stderr loses no signal it needs.
_DEVNULL_ERRLOG = open(os.devnull, "w")  # noqa: SIM115 - process-lifetime sink

_DEFAULT_CALL_TIMEOUT_S = 60.0


def mcp_enabled() -> bool:
    return os.environ.get("SPLUNKOLOGY_USE_MCP", "").strip().lower() in _TRUTHY


def _call_timeout_s() -> float:
    """Per-call wall-clock bound. Converts any stall into a recoverable FAIL."""
    raw = os.environ.get("SPLUNKOLOGY_MCP_CALL_TIMEOUT", "")
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_CALL_TIMEOUT_S
    return v if v > 0 else _DEFAULT_CALL_TIMEOUT_S


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
        async with stdio_client(params, errlog=_DEVNULL_ERRLOG) as (read, write):  # noqa: SIM117
            async with ClientSession(read, write) as session:
                await session.initialize()
                resp = await session.call_tool(name, arguments=args)
                text = "".join(
                    getattr(b, "text", "")
                    for b in resp.content
                    if getattr(b, "type", None) == "text"
                )
                return text, bool(getattr(resp, "isError", False))

    async def _attempt_bounded(self, name: str, args: dict, timeout: float) -> tuple[str, bool]:
        """Run one _attempt under a hard wall-clock bound.

        Uses a task + asyncio.wait (not wait_for) so a stalled/uncancellable
        teardown can't keep us blocked: on timeout we best-effort cancel and
        return, rather than awaiting the cancellation to complete.
        """
        task = asyncio.ensure_future(self._attempt(name, args))
        done, _pending = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            task.cancel()
            raise TimeoutError(f"MCP call '{name}' exceeded {timeout:.0f}s")
        return task.result()

    def _fail(self, name: str, message: str, t0: float) -> SocResult:
        return SocResult(
            tool=name,
            outcome=ToolOutcome.FAIL,
            summary=message,
            duration_ms=int((time.monotonic() - t0) * 1000),
            error=message,
        )

    async def call(self, name: str, args: dict) -> SocResult:
        """Always returns a SocResult \u2014 never hangs, never propagates.

        Any stall (e.g. a child blocked on a full stderr pipe), transport error,
        tool error, or malformed payload becomes a FAIL the agent recovers from,
        matching the direct-dispatch path's behaviour.
        """
        async with self._lock:
            t0 = time.monotonic()
            timeout = _call_timeout_s()
            try:
                text, is_error = await self._attempt_bounded(name, args, timeout)
            except TimeoutError as exc:
                # A genuine stall \u2014 retrying would just stall again; fail fast.
                return self._fail(name, str(exc), t0)
            except Exception:
                # Transport failure: one retry of the full lifecycle.
                try:
                    text, is_error = await self._attempt_bounded(name, args, timeout)
                except Exception as exc:
                    return self._fail(name, str(exc), t0)
            duration_ms = int((time.monotonic() - t0) * 1000)
            print(f"  \u21aa via MCP server: {name}", file=sys.stderr)
            if is_error:
                return self._fail(name, text or "mcp tool error", t0)
            try:
                return _to_soc_result(name, text, duration_ms)
            except Exception as exc:
                return self._fail(name, f"malformed MCP result: {exc}", t0)

    async def aclose(self) -> None:
        return None


dispatcher = MCPDispatcher()
