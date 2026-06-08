"""Verdict bridging helpers shared across orchestrators.

Every orchestrator must populate the dashboard verdict rail on *every*
successful run — not just when the model emits a clean v2 AgentOutput.
``harvest_verdict`` produces an IncidentVerdict-shaped dict from whatever
signal is available, in priority order:

1. A structured verdict already parsed this turn (``structured``).
2. A v2 JSON block recoverable from the raw response text (``parsed_text``).
3. The ``verdict`` sub-object *salvaged* from JSON that is valid JSON but fails
   whole-AgentOutput validation (e.g. a synthesis turn whose JSON is missing
   ``iteration_summary``/``next_action.rationale`` yet still carries a complete
   verdict block). This is the common synthesis-turn failure mode.
4. A synthesised verdict built from accumulated findings + SPL searches.

The result always carries ``claim``, ``confidence``, ``mitre_techniques`` and
``spl_evidence`` so the frontend ``renderVerdict`` never falls back to the
placeholder.
"""

from __future__ import annotations

import json
from typing import Any

from splunkology.agent.output_validator import extract_json_block, parse_agent_output


def _salvage_verdict_from_text(text: str | None) -> dict[str, Any] | None:
    """Recover a ``verdict`` sub-object from a JSON block that parses as JSON but
    fails full AgentOutput validation.

    The native synthesis turn frequently emits valid JSON missing top-level
    required fields (``iteration_summary``, ``next_action.rationale``) while the
    nested ``verdict`` block — claim, confidence, MITRE, SPL — is fully intact.
    ``parse_agent_output`` rejects the whole object, so without this salvage the
    good verdict is thrown away.
    """
    block = extract_json_block(text or "")
    if not block:
        return None
    try:
        raw = json.loads(block)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    verdict = raw.get("verdict")
    if isinstance(verdict, dict) and verdict:
        return verdict
    return None


def _mitre_from_findings(findings: list[dict] | None) -> list[dict]:
    mitre: list[dict] = []
    seen: set[str] = set()
    for f in findings or []:
        tid = f.get("mitre_technique")
        if tid and tid not in seen:
            seen.add(tid)
            mitre.append(
                {
                    "technique_id": tid,
                    "technique_name": "",
                    "confidence": f.get("confidence"),
                }
            )
    return mitre


def harvest_verdict(
    *,
    findings: list[dict] | None = None,
    spl_evidence: list[dict] | None = None,
    structured: dict[str, Any] | None = None,
    parsed_text: str | None = None,
    claim_fallback: str = "Investigation complete",
) -> dict[str, Any]:
    """Build an IncidentVerdict-shaped dict from the best available signal."""
    if structured is not None:
        v = dict(structured)
        v.setdefault("claim", claim_fallback)
        v.setdefault("confidence", None)
        v.setdefault("mitre_techniques", [])
        v.setdefault("spl_evidence", [])
        return v

    if parsed_text:
        parsed, _ = parse_agent_output(parsed_text)
        if parsed is not None and parsed.verdict is not None:
            return parsed.verdict.to_incident_verdict().model_dump()

        # Salvage path: valid JSON that fails whole-AgentOutput validation but
        # still carries an intact verdict block (the synthesis-turn failure mode).
        salvaged = _salvage_verdict_from_text(parsed_text)
        if salvaged is not None:
            v = dict(salvaged)
            v.setdefault("claim", claim_fallback)
            v.setdefault("confidence", None)
            if not v.get("mitre_techniques"):
                v["mitre_techniques"] = _mitre_from_findings(findings)
            if not v.get("spl_evidence"):
                v["spl_evidence"] = list(spl_evidence or [])
            return v

    return {
        "claim": claim_fallback,
        "confidence": None,
        "mitre_techniques": _mitre_from_findings(findings),
        "spl_evidence": list(spl_evidence or []),
    }
