"""Incident loader — maps BOTS notable events to triage targets.

Replaces the forensic cases.loader. Same interface:
  list_case_ids() -> list[str]
  get_case(case_id) -> IncidentMeta | None

Phase 1: static BOTS dataset stubs (unblocks dashboard + tests).
Phase 2: live pull from Splunk notable events via SplunkClient.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IncidentMeta:
    case_id: str
    case_name: str
    threat_type: str
    description: str = ""


# Static BOTS v3 incident registry — expand as we load datasets
_REGISTRY: dict[str, IncidentMeta] = {
    "bots_apt": IncidentMeta(
        case_id="bots_apt",
        case_name="BOTS APT Intrusion",
        threat_type="apt",
        description="Advanced persistent threat lateral movement scenario.",
    ),
    "bots_ransomware": IncidentMeta(
        case_id="bots_ransomware",
        case_name="BOTS Ransomware",
        threat_type="ransomware",
        description="Ransomware infection and C2 beaconing.",
    ),
    "bots_web": IncidentMeta(
        case_id="bots_web",
        case_name="BOTS Web Attack",
        threat_type="web_attack",
        description="Web application attack including SQLi and web shell.",
    ),
    "bots_insider": IncidentMeta(
        case_id="bots_insider",
        case_name="BOTS Insider Threat",
        threat_type="insider",
        description="Insider data exfiltration scenario.",
    ),
}


def list_case_ids() -> list[str]:
    """Return all known BOTS case IDs."""
    return list(_REGISTRY.keys())


def get_case(case_id: str) -> IncidentMeta | None:
    """Return IncidentMeta for case_id, or None if not found."""
    return _REGISTRY.get(case_id)
