# Splunkology Tool Catalog

> Auto-generated from `src/splunkology/mcp_server/server.py`.
> Do **not** edit manually — run `make tool-catalog` to regenerate.

**3 forensic tools registered.** All tools are READ-ONLY.
Evidence integrity is enforced architecturally — destructive operations do not exist.

## Index

- [`splunk_search`](#splunk-search)
- [`splunk_indexes`](#splunk-indexes)
- [`splunk_server_info`](#splunk-server-info)

---

## splunk_search

**Description:** Run a SPL search against Splunk. Returns up to 1000 events. Use for BOTS triage: hunt IOCs, correlate events, build SPL evidence chains.

### Input Schema

| Parameter | Type | Required | Default | Notes |
|-----------|------|:--------:|---------|-------|
| `spl` | `string` | ✓ |  | SPL query (without leading 'search') |
| `earliest` | `string` |  | `-24h` |  |
| `latest` | `string` |  | `now` |  |


### Output

Returns [`SocResult`](../src/splunkology/models/soc.py) serialized as JSON.
Key fields: `tool` · `findings` · `evidence_refs` · `duration_ms` · `outcome` (`ok` | `partial` | `fail`)

### Example Invocation

```json
{
  "tool": "splunk_search",
  "arguments": {
    "spl": "<spl>"
  }
}
```

---

## splunk_indexes

**Description:** List all Splunk indexes with event counts and time ranges.

### Input Schema

_No inputs._


### Output

Returns [`SocResult`](../src/splunkology/models/soc.py) serialized as JSON.
Key fields: `tool` · `findings` · `evidence_refs` · `duration_ms` · `outcome` (`ok` | `partial` | `fail`)

### Example Invocation

```json
{
  "tool": "splunk_indexes",
  "arguments": {}
}
```

---

## splunk_server_info

**Description:** Return Splunk version, build, and host info.

### Input Schema

_No inputs._


### Output

Returns [`SocResult`](../src/splunkology/models/soc.py) serialized as JSON.
Key fields: `tool` · `findings` · `evidence_refs` · `duration_ms` · `outcome` (`ok` | `partial` | `fail`)

### Example Invocation

```json
{
  "tool": "splunk_server_info",
  "arguments": {}
}
```

---
