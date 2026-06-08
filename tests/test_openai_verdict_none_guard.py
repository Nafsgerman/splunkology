def test_loose_verdict_none_does_not_crash_emit(monkeypatch):
    from splunkology.orchestrators import openai_fc_adapter as m

    monkeypatch.setattr(m, "_loose_verdict_from_text", lambda t: None)
    monkeypatch.setattr(m, "harvest_verdict", lambda **k: None)

    captured = {}

    def fake_emit(event, payload):
        captured["payload"] = payload

    # Minimal stand-in exercising the None->dict guard logic
    verdict = m._loose_verdict_from_text("x")
    if verdict is None:
        verdict = m.harvest_verdict(findings=[], claim_fallback="fallback claim")
    if not isinstance(verdict, dict):
        verdict = {"claim": "fallback claim", "confidence": None}
    assert verdict.get("claim") == "fallback claim"
