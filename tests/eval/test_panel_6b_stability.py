"""Tests for panel_6b_stability — does not require real seed run data."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")

from unittest.mock import MagicMock, patch

import matplotlib.pyplot as plt


def _make_ax():
    _fig, ax = plt.subplots()
    return ax


def test_placeholder_when_no_runs():
    from splunkology.eval.analytics import panel_6b_stability

    ax = _make_ax()
    # patch at the call site — lazy import inside render() means we mock
    # the function on the ablation_runner module object directly
    mock_module = MagicMock()
    mock_module.load_seed_results.return_value = []
    with patch.dict("sys.modules", {"splunkology.eval.ablation_runner": mock_module}):
        result = panel_6b_stability.render(ax, case_id="TEST-001")
    assert result["status"] == "placeholder"
    plt.close("all")


def test_sigma_style_stable():
    from splunkology.eval.analytics.panel_6b_stability import _sigma_style

    _color, lw, warn = _sigma_style(0.01)
    assert warn == ""
    assert lw < 2.0


def test_sigma_style_warn():
    from splunkology.eval.analytics.panel_6b_stability import _sigma_style

    _color, lw, warn = _sigma_style(0.03)
    assert warn == ""
    assert lw >= 2.0


def test_sigma_style_bad():
    from splunkology.eval.analytics.panel_6b_stability import RED, _sigma_style

    color, lw, warn = _sigma_style(0.06)
    assert color == RED
    assert "⚠" in warn
    assert lw >= 3.0


def test_claim_string():
    from splunkology.eval.analytics.panel_6b_stability import CLAIM

    assert "reproducible" in CLAIM
    assert "lucky" in CLAIM
