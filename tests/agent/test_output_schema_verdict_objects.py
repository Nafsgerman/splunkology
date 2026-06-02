"""Verdict nested-object schema coverage (Task 2 wiring)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from splunkology.agent.output_schema import (
    AgentOutput,
    MitreMappingOutput,
    SplEvidenceOutput,
    VerdictOutput,
)


def _finding(fid: str, conf: float) -> dict:
    return {
        "id": fid,
        "type": "process",
        "value": "license_ctrl.e",
        "confidence": conf,
        "evidence_excerpt": '"Owner": "license_ctrl.e", "PID": 1716',
        "reasoning": "single strong indicator",
    }


def test_verdict_mitre_and_spl_as_objects_parses() -> None:
    out = AgentOutput.model_validate(
        {
            "iteration_summary": "verdict turn",
            "next_action": {"decision": "verdict", "tool_to_call": None, "rationale": "answered"},
            "findings": [_finding("f1", 0.80)],
            "verdict": {
                "claim": "C2 over DNS confirmed",
                "confidence": 0.80,
                "supporting_finding_ids": ["f1"],
                "reasoning": "r" * 20,
                "mitre_techniques": [
                    {"technique_id": "T1071", "technique_name": "Application Layer Protocol"}
                ],
                "spl_evidence": [
                    {"spl": "index=botsv3 sourcetype=stream:dns | stats count by query"}
                ],
            },
        }
    )
    assert isinstance(out.verdict.mitre_techniques[0], MitreMappingOutput)
    assert out.verdict.mitre_techniques[0].technique_id == "T1071"
    assert isinstance(out.verdict.spl_evidence[0], SplEvidenceOutput)
    assert out.verdict.spl_evidence[0].result_count is None


def test_verdict_flat_mitre_strings_rejected() -> None:
    with pytest.raises(ValidationError):
        VerdictOutput.model_validate(
            {
                "claim": "c",
                "confidence": 0.5,
                "supporting_finding_ids": ["f1"],
                "reasoning": "r" * 20,
                "mitre_techniques": ["T1071"],
            }
        )


def test_verdict_defaults_empty_evidence() -> None:
    v = VerdictOutput.model_validate(
        {
            "claim": "c",
            "confidence": 0.5,
            "supporting_finding_ids": ["f1"],
            "reasoning": "r" * 20,
        }
    )
    assert v.mitre_techniques == []
    assert v.spl_evidence == []


def test_to_incident_verdict_maps_fields() -> None:
    v = VerdictOutput.model_validate(
        {
            "claim": "C2 confirmed",
            "confidence": 0.70,
            "supporting_finding_ids": ["f1"],
            "reasoning": "r" * 20,
            "mitre_techniques": [
                {"technique_id": "T1055", "technique_name": "Process Injection"}
            ],
            "spl_evidence": [{"spl": "index=botsv3 | head 1"}],
        }
    )
    iv = v.to_incident_verdict()
    assert iv.claim == "C2 confirmed"
    assert iv.mitre_techniques[0].technique_id == "T1055"
    assert iv.spl_evidence[0].spl == "index=botsv3 | head 1"
