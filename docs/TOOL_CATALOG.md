# Splunkology Tool Catalog

Auto-generated from `src/splunkology/mcp_server/server.py`. Do not edit manually.
Run `python scripts/generate_tool_catalog.py` to regenerate.

| Tool | Description | Required Parameters | Optional Parameters |
|------|-------------|---------------------|---------------------|
| `splunk_search` | Run a SPL search against Splunk. Returns up to 1000 events. Use for BOTS triage: hunt IOCs, correlate events, build SPL evidence chains. | `spl` (string) | `earliest` (string), `latest` (string) |
| `splunk_indexes` | List all Splunk indexes with event counts and time ranges. | — | — |
| `splunk_server_info` | Return Splunk version, build, and host info. | — | — |
