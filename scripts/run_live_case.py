"""Live BOTS triage — drives the v2 agent loop against the running Splunk container.

Usage: python3 scripts/run_live_case.py
Requires env: ANTHROPIC_API_KEY, SPLUNK_PASS (SPLUNK_URL/SPLUNK_USER optional).

On a structured-verdict run this also dumps runs/verdict-<run_id>.json and
runs/report-<run_id>.md for the checkpoint scorer. Report-based early-exit runs
emit no structured verdict; the harness reports that rather than writing a stub.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    from splunkology.agent.loop_v2 import run_case_v2
except ImportError:
    from splunkology.eval.loop_v2 import run_case_v2

BRIEFING = (
    "You are an autonomous SOC analyst triaging the Splunk index `botsv3` "
    "(Boss of the SOC v3 dataset, a historical capture from August 2018). "
    "Investigate for signs of compromise: suspicious processes, command-and-control "
    "beaconing, credential access, and data exfiltration. First call splunk_indexes "
    "to confirm the index exists, then use splunk_search to hunt. CRITICAL: always "
    "pass earliest='0' and latest='now' to splunk_search, because the data is "
    "historical and a relative time window will return zero events. Correlate your "
    "findings, map them to MITRE ATT&CK techniques, and return a verdict with a "
    "confidence score."
)


def _require(var: str) -> None:
    if not os.environ.get(var):
        sys.exit(f"Missing required env var: {var}")


async def _main() -> None:
    for var in ("ANTHROPIC_API_KEY", "SPLUNK_PASS"):
        _require(var)
    Path("./audit").mkdir(parents=True, exist_ok=True)
    runs_dir = Path("./runs")
    runs_dir.mkdir(parents=True, exist_ok=True)

    captured: dict[str, object] = {"verdict": None}

    def _on_event(event_type: str, data: dict) -> None:
        if event_type == "verdict_reached" and data.get("verdict"):
            captured["verdict"] = data["verdict"]

    report, run_id = await run_case_v2(
        case_id="bots-frothy-triage",
        evidence_files={},
        briefing=BRIEFING,
        audit_db="./audit/splunkology.db",
        on_event=_on_event,
    )

    (runs_dir / f"report-{run_id}.md").write_text(report, encoding="utf-8")
    if captured["verdict"]:
        verdict_path = runs_dir / f"verdict-{run_id}.json"
        verdict_path.write_text(json.dumps(captured["verdict"], indent=2), encoding="utf-8")
        print(f"\nverdict dumped: {verdict_path}")
    else:
        print("\nNo structured verdict captured this run. Nothing to score.")

    print("\n" + "=" * 70)
    print(f"run_id: {run_id}")
    print("=" * 70)
    print(report)


if __name__ == "__main__":
    asyncio.run(_main())
