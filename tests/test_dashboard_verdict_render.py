import asyncio

from splunkology.dashboard import app as m


def test_coerce_verdict_keeps_confidence_and_mitre():
    report_dict = {
        "verdict": "CONFIRMED — Active C2 Beaconing over DNS",
        "confidence": 0.97,
        "mitre_techniques": [
            {"technique_id": "T1071.004", "technique_name": "DNS"},
            {"technique_id": "T1568.002", "technique_name": "DGA"},
            {"technique_id": "T1048.003", "technique_name": "Exfil over DNS"},
            {"technique_id": "T1078", "technique_name": "Valid Accounts"},
        ],
        "key_evidence_excerpts": ["src_ip=172.16.0.109 count=27857", "median_interval=0.9856s"],
    }
    v = m._coerce_verdict(report_dict)
    assert v["claim"].startswith("CONFIRMED")
    assert v["confidence"] == 0.97
    assert len(v["mitre_techniques"]) == 4
    assert len(v["spl_evidence"]) >= 1


def test_stream_delivers_events_after_history():
    async def _inner():
        sid = "sess-late"
        for d in (m._sessions, m._queues, m._stream_gen):
            d.pop(sid, None)
        m._sessions[sid] = [{"type": "start", "case_id": "INC-001"}]
        m._queues[sid] = asyncio.Queue()

        class _Req:
            async def is_disconnected(self):
                return False

        resp = await m.stream(sid, _Req())
        agen = resp.body_iterator
        first = await asyncio.wait_for(agen.__anext__(), 2)
        assert "start" in first
        await m.push_event(sid, {"type": "iteration", "n": 7})
        seen = ""
        for _ in range(6):
            seen += await asyncio.wait_for(agen.__anext__(), 2)
            if "iteration" in seen and "7" in seen:
                break
        await agen.aclose()
        assert "iteration" in seen and "7" in seen

    asyncio.run(_inner())
