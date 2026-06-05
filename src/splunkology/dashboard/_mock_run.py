"""TEMPORARY mock triage runner — UI smoke test only. Delete after verifying.

Bypasses the LLM and Splunk entirely; fires a scripted on_event sequence so
the dashboard's verdict card / MITRE chips / SPL blocks / entity graph can be
verified with zero API spend. Not imported by anything except the 'mock'
orchestrator branch in app.py.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from splunkology.agent.output_schema import VerdictOutput


async def run_case_mock(
    case_id: str,
    evidence_files: dict[str, str],
    briefing: str,
    audit_db: str = "",
    training_mode: bool = False,
    on_event: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> tuple[str, str]:
    def emit(t: str, d: dict) -> None:
        if on_event:
            on_event(t, d)

    emit("investigation_started", {"run_id": "mock-run", "case_id": case_id, "model": "mock"})
    await asyncio.sleep(0.4)

    emit("iteration_complete", {"iteration": 0, "findings_count": 0, "iocs_count": 0})
    emit(
        "tool_call_start",
        {
            "tool": "splunk_search",
            "iteration": 0,
            "args": {"spl": "index=botsv3 sourcetype=stream:dns | stats count by query"},
        },
    )
    await asyncio.sleep(0.5)
    emit(
        "tool_call_end",
        {
            "tool": "splunk_search",
            "outcome": "ok",
            "summary": "428 events in 612ms",
            "duration_ms": 612,
            "iteration": 0,
        },
    )

    emit(
        "ioc_detected",
        {"type": "process", "value": "powershell.exe", "confidence": 0.82, "iteration": 1},
    )
    await asyncio.sleep(0.3)
    emit(
        "ioc_detected", {"type": "ip", "value": "45.77.65.211", "confidence": 0.74, "iteration": 1}
    )
    await asyncio.sleep(0.3)
    emit(
        "ioc_detected",
        {"type": "technique", "value": "T1071.004", "confidence": 0.78, "iteration": 1},
    )
    await asyncio.sleep(0.3)

    emit(
        "hypothesis_update",
        {"iteration": 1, "events": [{"content": "DNS tunneling C2 from a single host"}]},
    )
    await asyncio.sleep(0.4)

    verdict = VerdictOutput.model_validate(
        {
            "claim": "Confirmed C2 over DNS tunneling from host WIN-DC01 to 45.77.65.211.",
            "confidence": 0.74,
            "supporting_finding_ids": ["mock-f1"],
            "reasoning": "High-entropy DNS queries to a single resolver, beaconing interval consistent with C2, originating from a powershell.exe child process.",
            "mitre_techniques": [
                {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS"},
                {"technique_id": "T1572", "technique_name": "Protocol Tunneling"},
            ],
            "spl_evidence": [
                {"spl": "index=botsv3 sourcetype=stream:dns | stats count by query | sort -count"},
                {
                    "spl": "index=botsv3 sourcetype=stream:dns query=*.45-77-65-211.* | table _time query src_ip"
                },
            ],
        }
    )

    emit(
        "verdict_reached",
        {
            "run_id": "mock-run",
            "claim": verdict.claim,
            "confidence": verdict.confidence,
            "findings_count": 3,
            "total_cost_usd": 0.0,
            "verdict": verdict.to_incident_verdict().model_dump(mode="json"),
        },
    )
    await asyncio.sleep(0)  # yield to event loop so verdict task flushes before return

    report = "## Executive Summary\nMOCK RUN — UI smoke test. " + verdict.claim
    return report, "mock-run"
