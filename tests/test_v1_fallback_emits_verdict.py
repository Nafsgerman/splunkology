from splunkology.agent.loop_v2 import _synthesize_v1_fallback


def test_v1_fallback_decision_is_verdict():
    out = _synthesize_v1_fallback("Some long v1 report text about footprintdns.com C2", 11)
    assert out.next_action.decision == "verdict"
