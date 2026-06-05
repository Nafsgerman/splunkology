"""Offline proof of the verdict-emission path — no API calls.

Feeds a hand-built synthesis-turn response through the same chain the live
harness uses (parse_agent_output -> verdict -> to_incident_verdict ->
model_dump -> dump file -> checkpoint score). Proves emission + scoring
work end-to-end before spending on a live run.
"""

from __future__ import annotations

import json

from splunkology.agent.output_validator import parse_agent_output
from splunkology.eval.checkpoint_scorer import DEFAULT_CHECKPOINTS, load_checkpoints, score

SYNTHESIS_RESPONSE = """
## Executive Summary
Struts RCE led to a root backdoor, kernel LPE, IAM abuse, AWS cryptomining, and C2.

```json
{
  "iteration_summary": "Final synthesis: chain confirmed across web, host, and AWS logs.",
  "findings": [
    {
      "id": "f-struts",
      "type": "technique",
      "value": "Apache Struts OGNL RCE",
      "confidence": 0.85,
      "evidence_excerpt": "form_data contains OGNL expression invoking ProcessBuilder",
      "supporting_audit_entry_ids": [],
      "mitre_technique": "T1190",
      "reasoning": "Malicious OGNL in multipart form data on the public web server."
    },
    {
      "id": "f-crypto",
      "type": "technique",
      "value": "AWS RunInstances cryptomining via web_admin",
      "confidence": 0.8,
      "evidence_excerpt": "RunInstances called by user web_admin launching GPU instances",
      "supporting_audit_entry_ids": [],
      "mitre_technique": "T1496",
      "reasoning": "web_admin identity abused to launch mining instances."
    }
  ],
  "hypotheses": [],
  "next_action": {
    "decision": "verdict",
    "tool_to_call": null,
    "rationale": "Mission questions answered with high confidence."
  },
  "verdict": {
    "claim": "Struts OGNL RCE to root backdoor, kernel LPE, then web_admin AWS cryptomining and C2.",
    "confidence": 0.78,
    "supporting_finding_ids": ["f-struts", "f-crypto"],
    "reasoning": "Initial access via Struts, escalation, IAM abuse, and cryptomining are all evidenced in the indexed events with corroborating searches.",
    "mitre_techniques": [
      {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
      {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"},
      {"technique_id": "T1496", "technique_name": "Resource Hijacking"}
    ],
    "spl_evidence": [
      {"spl": "index=botsv3 sourcetype=stream:http struts ognl"},
      {"spl": "index=botsv3 RunInstances web_admin"}
    ]
  }
}
```
"""


def test_synthesis_response_parses_and_validates():
    out, err = parse_agent_output(SYNTHESIS_RESPONSE)
    assert err is None, err
    assert out is not None
    assert out.verdict is not None
    assert out.next_action.decision == "verdict"


def test_confidence_aggregation_satisfied():
    out, err = parse_agent_output(SYNTHESIS_RESPONSE)
    assert err is None, err
    min_finding = min(
        f.confidence for f in out.findings if f.id in out.verdict.supporting_finding_ids
    )
    assert out.verdict.confidence <= min_finding + 1e-6


def test_emission_chain_dumps_scorable_verdict(tmp_path):
    out, err = parse_agent_output(SYNTHESIS_RESPONSE)
    assert err is None, err
    iv = out.verdict.to_incident_verdict()
    path = tmp_path / "verdict-offline.json"
    path.write_text(json.dumps(iv.model_dump(), indent=2), encoding="utf-8")

    verdict = json.loads(path.read_text(encoding="utf-8"))
    report = score(verdict, load_checkpoints(DEFAULT_CHECKPOINTS))
    assert report.hits >= 3
    assert report.applicable == 13
