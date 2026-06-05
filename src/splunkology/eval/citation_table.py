"""Side-by-side citation table generator.

Renders a Markdown comparison of the agent's IncidentVerdict against the
analyst-verified BOTS v3 attack-chain checkpoints: one row per checkpoint,
showing the official answer, what the agent claimed, and whether it matched.

Reuses checkpoint_scorer for all match logic — this module only formats.
No new ground truth, no metrics beyond the scorer's hits/applicable coverage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from splunkology.eval.checkpoint_scorer import (
    DEFAULT_CHECKPOINTS,
    load_checkpoints,
    load_verdict,
    score,
)

_STATUS_MARK = {"hit": "✅ match", "miss": "❌ miss"}


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _agent_cell(cp: dict[str, Any], status: str, matched_on: str | None) -> str:
    if status != "hit":
        return "_not asserted_"
    if matched_on == "mitre":
        ids = ", ".join(cp.get("expected_mitre", []))
        return f"mapped {ids}"
    return "asserted in verdict"


def render_markdown(verdict: dict[str, Any], checkpoints_doc: dict[str, Any]) -> str:
    report = score(verdict, checkpoints_doc)
    by_id = {r.id: r for r in report.results}

    lines = [
        f"# BOTS v3 Attack-Chain Citation Table — {report.dataset}/{report.subset}",
        "",
        f"**Coverage: {report.hits} / {report.applicable} checkpoints "
        f"({report.coverage:.0%})** on the attack-chain subset. "
        "Trivia questions are out of scope for triage and excluded by design.",
        "",
        "| BOTS Q | Category | Official answer | Agent finding | Result |",
        "| --- | --- | --- | --- | --- |",
    ]

    for cp in checkpoints_doc["checkpoints"]:
        r = by_id[cp["id"]]
        lines.append(
            "| {q} | {cat} | {claim} | {agent} | {mark} |".format(
                q=_escape(cp.get("bots_question", "")),
                cat=_escape(cp.get("category", "")),
                claim=_escape(cp.get("claim", "")),
                agent=_escape(_agent_cell(cp, r.status, r.matched_on)),
                mark=_STATUS_MARK.get(r.status, r.status),
            )
        )

    misses = [
        by_id[cp["id"]] for cp in checkpoints_doc["checkpoints"] if by_id[cp["id"]].status == "miss"
    ]
    if misses:
        lines += ["", "## Recorded misses", ""]
        for r in misses:
            lines.append(f"- **{r.bots_question} — {_escape(r.claim)}**")

    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the BOTS v3 citation table from a verdict."
    )
    parser.add_argument("--verdict", required=True, type=Path, help="Path to verdict-<run_id>.json")
    parser.add_argument("--checkpoints", type=Path, default=DEFAULT_CHECKPOINTS)
    parser.add_argument("--out", type=Path, help="Write Markdown here instead of stdout")
    args = parser.parse_args(argv)

    verdict = load_verdict(args.verdict)
    doc = load_checkpoints(args.checkpoints)
    md = render_markdown(verdict, doc)

    if args.out:
        args.out.write_text(md, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
