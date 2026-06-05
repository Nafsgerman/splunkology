"""Tests for the citation table generator."""

from __future__ import annotations

from splunkology.eval.checkpoint_scorer import DEFAULT_CHECKPOINTS, load_checkpoints
from splunkology.eval.citation_table import render_markdown
from tests.eval.test_checkpoint_scorer import VERIFIED_RUN_VERDICT


def test_table_has_one_row_per_checkpoint():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    md = render_markdown(VERIFIED_RUN_VERDICT, doc)
    body = md.split("| --- | --- | --- | --- | --- |\n", 1)[1]
    data_rows = [ln for ln in body.splitlines() if ln.startswith("| ")]
    assert len(data_rows) == len(doc["checkpoints"])


def test_table_marks_hits_and_misses():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    md = render_markdown(VERIFIED_RUN_VERDICT, doc)
    assert md.count("✅ match") == 6
    assert md.count("❌ miss") == 7


def test_misses_section_names_cve_and_windows_chain():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    md = render_markdown(VERIFIED_RUN_VERDICT, doc)
    misses_block = md.split("## Recorded misses", 1)[1]
    for token in ("CVE-2017-9791", "hdoor.exe", "svcvnc", "Password123!", "45.77.53.176"):
        assert token in misses_block


def test_coverage_line_uses_no_barred_metrics():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    md = render_markdown(VERIFIED_RUN_VERDICT, doc).lower()
    assert "f1" not in md
    assert "precision" not in md
    assert "coverage:" in md


def test_pipes_in_content_are_escaped():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    verdict = {
        "claim": "a | b pipe test",
        "confidence": 0.5,
        "mitre_techniques": [],
        "spl_evidence": [],
    }
    md = render_markdown(verdict, doc)
    for ln in md.splitlines():
        if ln.startswith("| "):
            assert ln.count("|") >= 6
