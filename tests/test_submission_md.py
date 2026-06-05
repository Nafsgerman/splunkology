"""Devpost SUBMISSION.md drift guard (Splunk-era)."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SUB = REPO_ROOT / "docs" / "devpost" / "SUBMISSION.md"
README = REPO_ROOT / "README.md"

TAGLINE = (
    "Autonomous SOC triage for Splunk — raw events to a MITRE ATT&CK–mapped "
    "incident verdict, with no analyst in the loop."
)


def _read() -> str:
    return SUB.read_text(encoding="utf-8")


def test_submission_exists() -> None:
    assert SUB.exists(), "docs/devpost/SUBMISSION.md missing"


def test_tagline_matches_readme_hero() -> None:
    assert TAGLINE in _read(), "submission must carry the canonical tagline verbatim"
    assert TAGLINE in README.read_text(encoding="utf-8"), (
        "README hero must carry the same canonical tagline verbatim"
    )


def test_discloses_retarget() -> None:
    text = _read().lower()
    assert "siftguard" in text, "submission must disclose the SIFTGuard lineage"


def test_no_fabricated_metrics() -> None:
    text = _read()
    for banned in ("2.72", "F1 =", "F1=", "15/15", "12/12", "0.867", "1.000"):
        assert banned not in text, (
            f"barred fabricated/forensic metric present in submission: {banned!r}"
        )


def test_no_forensic_dataset_refs() -> None:
    text = _read()
    for banned in ("TEST-001", "TEST-002", "TEST-003", "SRL-2018", "Schardt", "ROCBA"):
        assert banned not in text, f"forensic-era dataset reference must not appear: {banned!r}"


def test_evaluation_pending_stated() -> None:
    text = _read().lower()
    assert "pending" in text or "not yet measured" in text or "no" in text, (
        "submission must state evaluation is pending (no Splunk numbers yet)"
    )


def test_limitations_linked() -> None:
    assert "LIMITATIONS.md" in _read()


def test_no_broken_adr_007_link() -> None:
    assert "ADR-007" not in _read(), "ADR-007 is mid-rewrite — do not reference until it lands"
