"""Tests for the Splunk-native checkpoint scorer."""

from __future__ import annotations

from splunkology.eval.checkpoint_scorer import (
    DEFAULT_CHECKPOINTS,
    load_checkpoints,
    score,
)

VERIFIED_RUN_VERDICT = {
    "claim": (
        "Apache Struts OGNL RCE gave initial access; a backdoor ran as tomcat7 with "
        "UID=0, followed by a kernel privilege escalation to root. The web_admin "
        "identity was abused for AWS RunInstances cryptomining, with command and "
        "control beaconing from compromised endpoints. CVE-2017-5638 suspected."
    ),
    "confidence": 0.74,
    "mitre_techniques": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "confidence": 0.9,
        },
        {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "confidence": 0.8,
        },
        {"technique_id": "T1078", "technique_name": "Valid Accounts", "confidence": 0.7},
        {"technique_id": "T1496", "technique_name": "Resource Hijacking", "confidence": 0.85},
        {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "confidence": 0.6,
        },
    ],
    "spl_evidence": [
        {
            "spl": "index=botsv3 sourcetype=stream:http struts",
            "result_count": 12,
            "earliest": "0",
            "latest": "now",
            "job_id": "j1",
        },
        {
            "spl": "index=botsv3 RunInstances web_admin",
            "result_count": 4,
            "earliest": "0",
            "latest": "now",
            "job_id": "j2",
        },
    ],
}


def test_checkpoint_file_loads_and_is_well_formed():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    assert doc["dataset"] == "botsv3"
    assert doc["subset"] == "attack_chain"
    ids = [c["id"] for c in doc["checkpoints"]]
    assert len(ids) == len(set(ids))
    for c in doc["checkpoints"]:
        assert c["requires"] in {"mitre", "indicator", "either"}


def test_applicable_equals_total_no_exclusions():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    report = score(VERIFIED_RUN_VERDICT, doc)
    assert report.applicable == len(doc["checkpoints"])


def test_verified_run_hits_chain_and_names_misses():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    report = score(VERIFIED_RUN_VERDICT, doc)
    status = {r.id: r.status for r in report.results}

    for cp_id in (
        "cp-rce-entry-vector",
        "cp-backdoor-uid0",
        "cp-kernel-lpe",
        "cp-iam-abuse",
        "cp-cryptomining",
        "cp-c2-present",
    ):
        assert status[cp_id] == "hit", cp_id

    for cp_id in (
        "cp-cve-struts",
        "cp-cve-lpe",
        "cp-c2-endpoint",
        "cp-win-phish",
        "cp-win-hdoor",
        "cp-win-svcvnc",
        "cp-win-cred",
    ):
        assert status[cp_id] == "miss", cp_id

    assert report.hits == 6


def test_subtechnique_satisfies_parent_mitre():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    verdict = {
        "claim": "",
        "confidence": 0.5,
        "mitre_techniques": [
            {"technique_id": "T1071.004", "technique_name": "DNS", "confidence": 0.5}
        ],
        "spl_evidence": [],
    }
    report = score(verdict, doc)
    status = {r.id: (r.status, r.matched_on) for r in report.results}
    assert status["cp-c2-present"] == ("hit", "mitre")


def test_indicator_only_checkpoint_ignores_technique_presence():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    verdict = {
        "claim": "Struts RCE, CVE unknown",
        "confidence": 0.5,
        "mitre_techniques": [{"technique_id": "T1190", "technique_name": "x", "confidence": 0.5}],
        "spl_evidence": [],
    }
    report = score(verdict, doc)
    status = {r.id: r.status for r in report.results}
    assert status["cp-cve-struts"] == "miss"


def test_report_dict_emits_no_barred_metrics():
    doc = load_checkpoints(DEFAULT_CHECKPOINTS)
    keys = set(score(VERIFIED_RUN_VERDICT, doc).to_dict().keys())
    assert "f1" not in keys
    assert "precision" not in keys
    assert {"hits", "applicable", "coverage"} <= keys
