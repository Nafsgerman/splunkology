"""Splunk transport layer.

SplunkClient is the single seam between the agent and Splunk.
Today: REST /services/search/jobs (basic auth, no KVStore dependency).
Future: swap _transport for MCP Bearer — zero changes above this layer.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class SearchResult:
    spl: str
    earliest: str
    latest: str
    events: list[dict[str, Any]]
    event_count: int  # rows returned (capped by result_limit)
    result_count: int  # total events the job matched (uncapped)
    duration_ms: int
    job_id: str = ""
    is_truncated: bool = False


@dataclass
class IndexInfo:
    name: str
    total_event_count: int
    current_db_size_mb: float
    earliest_time: str
    latest_time: str


@dataclass
class SplunkServerInfo:
    version: str
    build: str
    host: str
    server_name: str


# ---------------------------------------------------------------------------
# Abstract transport — lets us swap REST → MCP later
# ---------------------------------------------------------------------------


class _Transport(ABC):
    @abstractmethod
    def search(
        self, spl: str, earliest: str, latest: str, result_limit: int = 1000
    ) -> SearchResult: ...

    @abstractmethod
    def list_indexes(self) -> list[IndexInfo]: ...

    @abstractmethod
    def server_info(self) -> SplunkServerInfo: ...


# ---------------------------------------------------------------------------
# REST transport (active)
# ---------------------------------------------------------------------------


class _RestTransport(_Transport):
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 60) -> None:
        self._base = base_url.rstrip("/")
        self._auth = (username, password)
        self._timeout = timeout
        self._session = requests.Session()
        self._session.verify = False

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self._session.get(
            f"{self._base}{path}",
            auth=self._auth,
            params={"output_mode": "json", **(params or {})},
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict) -> dict:
        r = self._session.post(
            f"{self._base}{path}",
            auth=self._auth,
            data={"output_mode": "json", **data},
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    def _job_info(self, sid: str) -> dict:
        data = self._get(f"/services/search/jobs/{sid}")
        return data["entry"][0]["content"]

    def search(
        self, spl: str, earliest: str = "-24h", latest: str = "now", result_limit: int = 1000
    ) -> SearchResult:
        t0 = time.monotonic()

        job = self._post(
            "/services/search/jobs",
            {
                "search": spl if spl.startswith("search ") else f"search {spl}",
                "earliest_time": earliest,
                "latest_time": latest,
                "exec_mode": "blocking",
            },
        )
        sid = job["sid"]

        info = self._job_info(sid)
        result_count = int(info.get("resultCount", 0))

        results = self._get(f"/services/search/jobs/{sid}/results", {"count": result_limit})
        events = results.get("results", [])

        return SearchResult(
            spl=spl,
            earliest=earliest,
            latest=latest,
            events=events,
            event_count=len(events),
            result_count=result_count,
            duration_ms=int((time.monotonic() - t0) * 1000),
            job_id=sid,
            is_truncated=result_count > len(events),
        )

    def list_indexes(self) -> list[IndexInfo]:
        data = self._get("/services/data/indexes", {"count": 100})
        out = []
        for entry in data.get("entry", []):
            c = entry.get("content", {})
            out.append(
                IndexInfo(
                    name=entry["name"],
                    total_event_count=int(c.get("totalEventCount", 0)),
                    current_db_size_mb=round(int(c.get("currentDBSizeMB", 0)), 2),
                    earliest_time=c.get("minTime", ""),
                    latest_time=c.get("maxTime", ""),
                )
            )
        return out

    def server_info(self) -> SplunkServerInfo:
        data = self._get("/services/server/info")
        content = data["entry"][0]["content"]
        return SplunkServerInfo(
            version=content.get("version", ""),
            build=content.get("build", ""),
            host=content.get("host", ""),
            server_name=content.get("serverName", ""),
        )


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------


class SplunkClient:
    """Single entry point for all Splunk I/O.

    Transport is injected — REST today, MCP-ready via _MCPTransport (TODO).
    """

    def __init__(
        self,
        base_url: str = "https://localhost:8089",
        username: str = "admin",
        password: str | None = None,
        *,
        transport: _Transport | None = None,
    ) -> None:
        if transport is None:
            if password is None:
                password = os.environ["SPLUNK_PASS"]  # fail loud if unset
            transport = _RestTransport(base_url, username, password)
        self._t: _Transport = transport

    # -- Core search ---------------------------------------------------------

    def search(
        self, spl: str, earliest: str = "-24h", latest: str = "now", result_limit: int = 1000
    ) -> SearchResult:
        """Run SPL query, return typed SearchResult."""
        return self._t.search(spl, earliest, latest, result_limit)

    # -- Discovery -----------------------------------------------------------

    def list_indexes(self) -> list[IndexInfo]:
        return self._t.list_indexes()

    def server_info(self) -> SplunkServerInfo:
        return self._t.server_info()

    # -- Convenience ---------------------------------------------------------

    def ping(self) -> bool:
        """True if Splunk is reachable and auth works."""
        try:
            self.server_info()
            return True
        except Exception:
            return False
