"""Splunk-native checkpoint scorer.

Standalone evaluator that scores an agent IncidentVerdict against the
analyst-verified BOTS v3 attack-chain checkpoints. Emits a coverage
fraction (hits / applicable) plus a per-checkpoint hit/miss breakdown.

This module does NOT import or share code with the legacy forensic
eval/scorer.py and emits no F1 or precision metrics by design. BOTS v3
is one continuous dataset, so every checkpoint is reachable and
applicable == total (no not-applicable exclusions).

Verdict input shape (IncidentVerdict.model_dump from models/soc.py):
    {
      "claim": str,
      "confidence": float,
      "mitre_techniques": [{"technique_id", "technique_name", "confidence"}],
      "spl_evidence": [{"spl", "result_count", "earliest", "latest", "job_id"}]
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DEFAULT_CHECKPOINTS = Path(__file__).parent / "checkpoints" / "botsv3_attack_chain.json"


@dataclass(frozen=True)
class CheckpointResult:
    id: str
    category: str
    bots_question: str
    claim: str
    status: str  # "hit" | "miss"
    matched_on: str | None  # "mitre" | "indicator" | None


@dataclass(frozen=True)
class ScoreReport:
    dataset: str
    subset: str
    hits: int
    applicable: int
    coverage: float
    results: list[CheckpointResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "subset": self.subset,
            "hits": self.hits,
            "applicable": self.applicable,
            "coverage": round(self.coverage, 4),
            "checkpoints": [asdict(r) for r in self.results],
        }


def load_checkpoints(path: Path = DEFAULT_CHECKPOINTS) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_verdict(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _verdict_blob(verdict: dict[str, Any]) -> str:
    """Concatenate every text surface of the verdict, lowercased, for indicator matching."""
    parts: list[str] = [str(verdict.get("claim", ""))]
    for ev in verdict.get("spl_evidence", []) or []:
        parts.append(str(ev.get("spl", "")))
    for mt in verdict.get("mitre_techniques", []) or []:
        parts.append(str(mt.get("technique_name", "")))
        parts.append(str(mt.get("technique_id", "")))
    return "\n".join(parts).lower()


def _verdict_mitre_ids(verdict: dict[str, Any]) -> set[str]:
    return {
        str(mt.get("technique_id", "")).upper().strip()
        for mt in verdict.get("mitre_techniques", []) or []
        if mt.get("technique_id")
    }


def _mitre_hit(expected: list[str], present: set[str]) -> bool:
    for exp in expected:
        e = exp.upper().strip()
        for p in present:
            if p == e or p.startswith(e + "."):
                return True
    return False


def _indicator_hit(expected: list[str], blob: str) -> bool:
    return any(tok.lower() in blob for tok in expected)


def score(verdict: dict[str, Any], checkpoints_doc: dict[str, Any]) -> ScoreReport:
    blob = _verdict_blob(verdict)
    present = _verdict_mitre_ids(verdict)
    results: list[CheckpointResult] = []

    for cp in checkpoints_doc["checkpoints"]:
        requires = cp.get("requires", "either")
        exp_mitre = cp.get("expected_mitre", []) or []
        exp_ind = cp.get("expected_indicators", []) or []

        mitre_ok = bool(exp_mitre) and _mitre_hit(exp_mitre, present)
        ind_ok = bool(exp_ind) and _indicator_hit(exp_ind, blob)

        if requires == "mitre":
            hit, matched = mitre_ok, ("mitre" if mitre_ok else None)
        elif requires == "indicator":
            hit, matched = ind_ok, ("indicator" if ind_ok else None)
        else:  # either
            hit = mitre_ok or ind_ok
            matched = "mitre" if mitre_ok else ("indicator" if ind_ok else None)

        results.append(
            CheckpointResult(
                id=cp["id"],
                category=cp.get("category", ""),
                bots_question=cp.get("bots_question", ""),
                claim=cp.get("claim", ""),
                status="hit" if hit else "miss",
                matched_on=matched,
            )
        )

    hits = sum(1 for r in results if r.status == "hit")
    applicable = len(results)
    coverage = hits / applicable if applicable else 0.0
    return ScoreReport(
        dataset=checkpoints_doc.get("dataset", ""),
        subset=checkpoints_doc.get("subset", ""),
        hits=hits,
        applicable=applicable,
        coverage=coverage,
        results=results,
    )


def render_text(report: ScoreReport) -> str:
    lines = [
        f"Checkpoint score — {report.dataset}/{report.subset}",
        f"  hits / applicable: {report.hits} / {report.applicable}  ({report.coverage:.0%})",
        "",
    ]
    width = max((len(r.id) for r in report.results), default=12)
    for r in report.results:
        mark = "PASS" if r.status == "hit" else "MISS"
        via = f" via {r.matched_on}" if r.matched_on else ""
        lines.append(f"  [{mark}] {r.id.ljust(width)}  {r.bots_question}{via}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score an IncidentVerdict against BOTS checkpoints."
    )
    parser.add_argument("--verdict", required=True, type=Path, help="Path to verdict-<run_id>.json")
    parser.add_argument("--checkpoints", type=Path, default=DEFAULT_CHECKPOINTS)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    verdict = load_verdict(args.verdict)
    doc = load_checkpoints(args.checkpoints)
    report = score(verdict, doc)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
