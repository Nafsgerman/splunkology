"""SOC domain models — replaces models/forensic.py.

ToolOutcome and SocResult mirror the SocResult interface so
loop_v2.py dispatch machinery needs minimal changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ToolOutcome(StrEnum):
    OK = "ok"
    FAIL = "fail"
    EMPTY = "empty"


@dataclass
class SocResult:
    """Typed result from any Splunk tool call — mirrors SocResult interface."""

    tool: str
    outcome: ToolOutcome
    summary: str
    duration_ms: int
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def model_dump_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(
            {
                "tool": self.tool,
                "outcome": self.outcome.value,
                "summary": self.summary,
                "duration_ms": self.duration_ms,
                "error": self.error,
                "raw": self.raw,
            },
            indent=indent,
        )


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    confidence: float | None = None


class SplEvidence(BaseModel):
    spl: str
    result_count: int = 0
    earliest: str = ""
    latest: str = ""
    job_id: str = ""


class IncidentVerdict(BaseModel):
    claim: str
    confidence: float
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    spl_evidence: list[SplEvidence] = Field(default_factory=list)
