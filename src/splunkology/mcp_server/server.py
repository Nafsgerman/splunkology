"""MCP server — Splunk tool surface.

Tools exposed to the agent loop:
  splunk_search      — run SPL, return events
  splunk_indexes     — list available indexes
  splunk_server_info — version/host check
"""
from __future__ import annotations

import asyncio
import os

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from splunkology.splunk.client import SplunkClient

app = Server("splunkology-mcp")

def _client() -> SplunkClient:
    return SplunkClient(
        base_url=os.environ.get("SPLUNK_URL", "https://localhost:8089"),
        username=os.environ.get("SPLUNK_USER", "admin"),
        password=os.environ["SPLUNK_PASS"],
    )


TOOLS = [
    Tool(
        name="splunk_search",
        description=(
            "Run a SPL search against Splunk. Returns up to 1000 events. "
            "Use for BOTS triage: hunt IOCs, correlate events, build SPL evidence chains."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "spl": {"type": "string", "description": "SPL query (without leading 'search')"},
                "earliest": {"type": "string", "default": "-24h"},
                "latest": {"type": "string", "default": "now"},
            },
            "required": ["spl"],
        },
    ),
    Tool(
        name="splunk_indexes",
        description="List all Splunk indexes with event counts and time ranges.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="splunk_server_info",
        description="Return Splunk version, build, and host info.",
        inputSchema={"type": "object", "properties": {}},
    ),
]


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = _client()

    if name == "splunk_search":
        result = client.search(
            spl=arguments["spl"],
            earliest=arguments.get("earliest", "-24h"),
            latest=arguments.get("latest", "now"),
        )
        import json
        payload = {
            "job_id": result.job_id,
            "event_count": result.event_count,
            "duration_ms": result.duration_ms,
            "events": result.events,
        }
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

    if name == "splunk_indexes":
        indexes = client.list_indexes()
        import json
        return [TextContent(type="text", text=json.dumps(
            [vars(i) for i in indexes], indent=2
        ))]

    if name == "splunk_server_info":
        info = client.server_info()
        import json
        return [TextContent(type="text", text=json.dumps(vars(info), indent=2))]

    raise ValueError(f"unknown tool: {name}")


def main() -> None:
    asyncio.run(_run())


async def _run() -> None:
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    main()
