"""SOC domain models — replaces models/forensic.py.

ToolOutcome and SocResult mirror the ForensicResult interface so
loop_v2.py dispatch machinery needs minimal changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ToolOutcome(StrEnum):
    OK = "ok"
    FAIL = "fail"
    EMPTY = "empty"


@dataclass
class SocResult:
    """Typed result from any Splunk tool call — mirrors ForensicResult interface."""
    tool: str
    outcome: ToolOutcome
    summary: str
    duration_ms: int
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def model_dump_json(self, indent: int = 2) -> str:
        import json
        return json.dumps({
            "tool": self.tool,
            "outcome": self.outcome.value,
            "summary": self.summary,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "raw": self.raw,
        }, indent=indent)


@dataclass
class MitreMapping:
    technique_id: str   # e.g. T1059.001
    technique_name: str
    confidence: float   # 0.0–1.0


@dataclass
class SplEvidence:
    spl: str
    result_count: int
    earliest: str
    latest: str
    job_id: str = ""


@dataclass
class IncidentVerdict:
    claim: str
    confidence: float
    mitre_techniques: list[MitreMapping] = field(default_factory=list)
    spl_evidence: list[SplEvidence] = field(default_factory=list)
