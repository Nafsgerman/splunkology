"""Offline proof for the verdict-rail parity fixes across orchestrators.

Covers:
- Bug 1 (native): every exit path emits a structured verdict payload.
- Bug 2 (OpenAI FC): GPT-shaped verdict JSON is coerced + loosely parsed.
- Bug 3 (LangGraph): forced synthesis turn + verdict emission.
- Bug 4 (Gemini): client teardown guard neutralises the async finalizer.

No live API calls — pure function-level assertions.
"""

from __future__ import annotations

import json

import pytest

from splunkology.agent.output_schema import VerdictOutput
from splunkology.agent.output_validator import parse_agent_output
from splunkology.agent.verdict_bridge import harvest_verdict
from splunkology.dashboard.app import (
    _coerce_verdict,
    _normalize_confidence,
    _normalize_mitre,
)

# Reproduction of the dashboard synthesis-turn failure: VALID JSON that fails
# whole-AgentOutput validation (missing iteration_summary; next_action missing
# rationale) while carrying a fully intact verdict block. This is the exact
# shape that left the rail empty.
_SYNTH_MITRE = [
    {"technique_id": tid, "technique_name": name}
    for tid, name in [
        ("T1071.004", "Application Layer Protocol: DNS"),
        ("T1071.001", "Application Layer Protocol: Web"),
        ("T1568.002", "Dynamic Resolution: DGA"),
        ("T1041", "Exfiltration Over C2 Channel"),
        ("T1573", "Encrypted Channel"),
        ("T1090", "Proxy"),
        ("T1095", "Non-Application Layer Protocol"),
        ("T1132", "Data Encoding"),
        ("T1572", "Protocol Tunneling"),
        ("T1008", "Fallback Channels"),
        ("T1583.001", "Acquire Infrastructure: Domains"),
    ]
]
_SYNTH_SPL = [{"spl": f"index=botsv3 q{i}"} for i in range(7)]
_MALFORMED_SYNTH_JSON = (
    "## Executive Summary\nC2 confirmed.\n\n```json\n"
    + json.dumps(
        {
            "next_action": {"decision": "verdict"},
            "findings": [],
            "verdict": {
                "claim": "Confirmed C2 beacon: 172.16.197.137 -> resolve.acrobatverify.com",
                "confidence": 0.91,
                "supporting_finding_ids": [],
                "reasoning": "Periodic DNS beacon to a newly-registered domain.",
                "mitre_techniques": _SYNTH_MITRE,
                "spl_evidence": _SYNTH_SPL,
            },
        }
    )
    + "\n```"
)

# ── Bug 2: dashboard coercion of the GPT shape ──────────────────────────────


def test_coerce_verdict_openai_shape_string_confidence_and_attck_mapping():
    raw = {
        "claim": "DNS tunnelling C2 confirmed",
        "confidence": "medium_high",
        "attck_mapping": ["T1071.004", {"id": "T1048", "name": "Exfil over alt proto"}],
    }
    v = _coerce_verdict(raw)
    assert v["claim"] == "DNS tunnelling C2 confirmed"
    assert v["confidence"] == 0.7
    ids = [m["technique_id"] for m in v["mitre_techniques"]]
    assert ids == ["T1071.004", "T1048"]
    assert v["mitre_techniques"][1]["technique_name"] == "Exfil over alt proto"


def test_coerce_verdict_verdict_as_bare_string_becomes_claim():
    v = _coerce_verdict({"verdict": "malicious", "confidence": "high"})
    assert v["claim"] == "malicious"
    assert v["confidence"] == 0.8


def test_normalize_confidence_forms():
    assert _normalize_confidence("medium_high") == 0.7
    assert _normalize_confidence("70%") == 0.7
    assert _normalize_confidence("0.7") == 0.7
    assert _normalize_confidence(70) == 0.7
    assert _normalize_confidence(0.7) == 0.7
    assert _normalize_confidence("gibberish") is None
    assert _normalize_confidence(None) is None


def test_normalize_mitre_mixed_shapes():
    out = _normalize_mitre(["T1059", {"technique_id": "T1071", "technique_name": "App Layer"}])
    assert out[0] == {"technique_id": "T1059", "technique_name": ""}
    assert out[1]["technique_name"] == "App Layer"


def test_coerce_verdict_passes_through_native_shape():
    native = (
        VerdictOutput(claim="x", confidence=0.9, supporting_finding_ids=[], reasoning="r")
        .to_incident_verdict()
        .model_dump()
    )
    v = _coerce_verdict(native)
    assert v["confidence"] == 0.9
    assert v["mitre_techniques"] == []


# ── Bug 2: OpenAI adapter loose-verdict extraction ──────────────────────────


def test_loose_verdict_from_text_extracts_gpt_block():
    from splunkology.orchestrators.openai_fc_adapter import _loose_verdict_from_text

    text = (
        "Here is my conclusion.\n\n"
        '```json\n{"verdict": "malicious", "confidence": "medium_high", '
        '"attck_mapping": ["T1071.004"]}\n```\n'
    )
    raw = _loose_verdict_from_text(text)
    assert raw is not None
    coerced = _coerce_verdict(raw)
    assert coerced["claim"] == "malicious"
    assert coerced["confidence"] == 0.7
    assert coerced["mitre_techniques"][0]["technique_id"] == "T1071.004"


def test_loose_verdict_from_text_none_when_no_block():
    from splunkology.orchestrators.openai_fc_adapter import _loose_verdict_from_text

    assert _loose_verdict_from_text("no json here") is None


# ── Bug 1 + 3: verdict bridge harvesting ────────────────────────────────────


def test_harvest_verdict_prefers_structured():
    structured = {"claim": "c", "confidence": 0.8, "mitre_techniques": [], "spl_evidence": []}
    v = harvest_verdict(structured=structured, findings=[], claim_fallback="fb")
    assert v["claim"] == "c"
    assert v["confidence"] == 0.8


def test_harvest_verdict_parses_v2_block_from_text():
    text = (
        '```json\n{"iteration_summary":"s","next_action":{"decision":"verdict",'
        '"rationale":"r"},"findings":[],"verdict":{"claim":"beaconing confirmed",'
        '"confidence":0.82,"supporting_finding_ids":[],"reasoning":"r",'
        '"mitre_techniques":[{"technique_id":"T1071","technique_name":"App Layer"}],'
        '"spl_evidence":[{"spl":"index=dns"}]}}\n```'
    )
    v = harvest_verdict(parsed_text=text, findings=[], claim_fallback="fb")
    assert v["claim"] == "beaconing confirmed"
    assert v["confidence"] == 0.82
    assert v["mitre_techniques"][0]["technique_id"] == "T1071"


def test_harvest_verdict_synthesizes_mitre_from_findings():
    findings = [
        {"type": "process", "value": "evil.exe", "mitre_technique": "T1059", "confidence": 0.7},
        {"type": "ip", "value": "1.2.3.4", "mitre_technique": "T1071", "confidence": 0.6},
        {"type": "ip", "value": "5.6.7.8", "mitre_technique": "T1071", "confidence": 0.5},
    ]
    spl = [{"spl": "index=dns", "result_count": 12}]
    v = harvest_verdict(
        findings=findings, spl_evidence=spl, parsed_text="", claim_fallback="report-based exit"
    )
    assert v["claim"] == "report-based exit"
    ids = sorted(m["technique_id"] for m in v["mitre_techniques"])
    assert ids == ["T1059", "T1071"]
    assert v["spl_evidence"] == spl


# ── Bug 1: native payload helper always carries a verdict ───────────────────


def test_native_verdict_payload_always_has_verdict():
    from splunkology.agent.loop_v2 import V2RunState, _native_verdict_payload

    state = V2RunState(run_id="r1", case_id="C", model="m")
    state.all_findings = [
        {"type": "process", "value": "x.exe", "mitre_technique": "T1059", "confidence": 0.8}
    ]
    state.spl_searches = [{"spl": "index=main", "result_count": 3}]
    payload = _native_verdict_payload(state, None, "", "Investigation complete (report-based exit)")
    assert "verdict" in payload
    assert payload["verdict"]["claim"] == "Investigation complete (report-based exit)"
    assert payload["verdict"]["mitre_techniques"][0]["technique_id"] == "T1059"
    assert payload["verdict"]["spl_evidence"] == state.spl_searches


def test_malformed_synthesis_json_fails_full_agentoutput_parse():
    # Confirms the precondition: the whole-object parser rejects this JSON, so
    # the verdict would be lost without the salvage path.
    parsed, error = parse_agent_output(_MALFORMED_SYNTH_JSON)
    assert parsed is None
    assert error is not None
    assert "iteration_summary" in error
    assert "rationale" in error


def test_harvest_salvages_verdict_from_malformed_synthesis_json():
    v = harvest_verdict(
        findings=[],
        spl_evidence=[],
        parsed_text=_MALFORMED_SYNTH_JSON,
        claim_fallback="Investigation incomplete",
    )
    assert v["claim"].startswith("Confirmed C2 beacon")
    assert v["confidence"] == 0.91
    assert len(v["mitre_techniques"]) == 11
    assert v["mitre_techniques"][0]["technique_id"] == "T1071.004"
    assert len(v["spl_evidence"]) == 7


def test_harvest_salvage_backfills_spl_from_accumulator_when_verdict_lacks_it():
    block = (
        "## Executive Summary\nx\n\n```json\n"
        + json.dumps(
            {
                "next_action": {"decision": "verdict"},
                "verdict": {
                    "claim": "C2 confirmed",
                    "confidence": 0.8,
                    "supporting_finding_ids": [],
                    "reasoning": "r",
                    "mitre_techniques": [{"technique_id": "T1071", "technique_name": "App"}],
                },
            }
        )
        + "\n```"
    )
    acc = [{"spl": "index=botsv3 dns", "result_count": 42}]
    v = harvest_verdict(findings=[], spl_evidence=acc, parsed_text=block, claim_fallback="fb")
    assert v["claim"] == "C2 confirmed"
    assert v["spl_evidence"] == acc


def test_native_payload_renders_salvaged_verdict_through_coerce():
    # End-to-end of the dashboard path: payload -> _coerce_verdict -> rail shape.
    from splunkology.agent.loop_v2 import V2RunState, _native_verdict_payload

    state = V2RunState(run_id="r", case_id="C", model="m")
    payload = _native_verdict_payload(
        state, None, _MALFORMED_SYNTH_JSON, "Investigation incomplete"
    )
    assert "verdict" in payload
    coerced = _coerce_verdict(payload["verdict"])
    assert coerced["claim"].startswith("Confirmed C2 beacon")
    assert coerced["confidence"] == 0.91
    assert len(coerced["mitre_techniques"]) == 11
    assert len(coerced["spl_evidence"]) == 7


@pytest.mark.asyncio
async def test_run_case_v2_safety_net_emits_verdict_on_malformed_truncated_synthesis(monkeypatch):
    # Full-loop proof: a forced-synthesis turn returns malformed JSON AND is
    # truncated (stop_reason='max_tokens'), so the normal end_turn emission is
    # skipped. The post-loop safety net must still emit the salvaged verdict.
    from unittest.mock import MagicMock, patch

    import splunkology.agent.loop_v2 as loop

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    block = MagicMock()
    block.type = "text"
    block.text = _MALFORMED_SYNTH_JSON
    resp = MagicMock()
    resp.content = [block]
    resp.usage.input_tokens = 10
    resp.usage.output_tokens = 20
    resp.stop_reason = "max_tokens"

    mock_client = MagicMock()
    mock_client.messages.create.return_value = resp

    mock_audit = MagicMock()
    mock_audit.for_case.return_value = []

    events: list[tuple[str, dict]] = []

    with (
        patch.object(loop.anthropic, "Anthropic", return_value=mock_client),
        patch.object(loop, "SnapshotWriter", return_value=MagicMock()),
        patch.object(loop, "AuditLog", return_value=mock_audit),
    ):
        await loop.run_case_v2(
            case_id="C",
            evidence_files={},
            briefing="b",
            audit_db=":memory:",
            max_iterations=1,
            on_event=lambda et, data: events.append((et, data)),
        )

    verdicts = [d for et, d in events if et == "verdict_reached"]
    assert len(verdicts) == 1, "exactly one verdict must reach the rail"
    v = verdicts[0]["verdict"]
    assert v["claim"].startswith("Confirmed C2 beacon")
    assert v["confidence"] == 0.91
    assert len(v["mitre_techniques"]) == 11
    assert len(v["spl_evidence"]) == 7


def test_synthesize_v1_fallback_returns_valid_agent_output():
    from splunkology.agent.loop_v2 import _synthesize_v1_fallback
    from splunkology.agent.output_schema import AgentOutput

    out = _synthesize_v1_fallback("some free-form v1 text", 3)
    assert isinstance(out, AgentOutput)
    assert out.next_action.decision == "verdict"
    assert out.verdict is None


# ── Bug 3: LangGraph forced synthesis routing ───────────────────────────────


def test_langgraph_router_forces_synthesis_before_max_iter():
    from unittest.mock import MagicMock

    from splunkology.orchestrators.langgraph_adapter import tool_router

    resp = MagicMock()
    resp.content = []
    resp.stop_reason = "end_turn"
    state = {
        "messages": [{"role": "assistant", "content": [], "_response": resp}],
        "iter_count": 14,
        "max_iter": 15,
        "final_report": "",
    }
    assert tool_router(state) == "synthesize"
    state["synth_done"] = True
    assert tool_router(state) == "end"


def test_langgraph_synthesize_node_sets_force_synth():
    from splunkology.orchestrators.langgraph_adapter import synthesize_node

    out = synthesize_node({"messages": []})
    assert out["force_synth"] is True
    assert out["synth_done"] is True
    assert out["messages"][-1]["role"] == "user"
    assert "FINAL TURN" in out["messages"][-1]["content"]


def test_langgraph_verdict_payload_from_findings():
    from splunkology.orchestrators.langgraph_adapter import _langgraph_verdict_payload

    final_state = {
        "all_findings": [
            {"type": "ip", "value": "1.2.3.4", "mitre_technique": "T1071", "confidence": 0.7}
        ],
        "messages": [],
        "final_report": "",
        "cumulative_cost_usd": 0.01,
    }
    payload = _langgraph_verdict_payload("rid", final_state)
    assert payload["verdict"]["mitre_techniques"][0]["technique_id"] == "T1071"


# ── Bug 4: Gemini teardown guard ────────────────────────────────────────────


def test_safe_close_genai_neutralizes_failing_aclose():
    import asyncio

    from splunkology.orchestrators.gemini_adapter import _safe_close_genai

    class FailingApiClient:
        # mimics google-genai BaseApiClient missing the attribute its aclose() needs
        def __init__(self):
            self.closed = False

        async def aclose(self):
            return self._async_httpx_client.aclose()  # would AttributeError

    class FakeClient:
        def __init__(self):
            self._api_client = FailingApiClient()

        def close(self):
            self._api_client.closed = True

    c = FakeClient()
    _safe_close_genai(c)
    assert c._api_client.closed is True
    # After the guard, the (replaced) aclose coroutine must not raise.
    asyncio.run(c._api_client.aclose())
