from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse


@dataclass
class ScanRecord:
    id: str
    url: str
    domain: str
    risk_score: int
    label: str
    confidence: float
    reasons: list[str]
    sources: dict
    risk_breakdown: list[dict]
    source_origin: str  # "extension" | "dashboard"
    timestamp: str


class RecentScansStore:
    def __init__(self, maxlen: int = 100) -> None:
        self._lock = threading.Lock()
        self._scans: deque[ScanRecord] = deque(maxlen=maxlen)

    def record(
        self,
        url: str,
        risk_score: int,
        label: str,
        confidence: float,
        reasons: list[str],
        sources: dict,
        risk_breakdown: list[dict],
        source_origin: str = "extension",
    ) -> ScanRecord:
        domain = urlparse(url).hostname or url
        scan_id = f"{int(time.time() * 1000)}"
        now_iso = datetime.now(timezone.utc).isoformat()

        record = ScanRecord(
            id=scan_id,
            url=url,
            domain=domain,
            risk_score=risk_score,
            label=label,
            confidence=confidence,
            reasons=reasons,
            sources=sources,
            risk_breakdown=risk_breakdown,
            source_origin=source_origin,
            timestamp=now_iso,
        )

        with self._lock:
            # Avoid consecutive duplicate records for same url within 3 seconds
            if self._scans and self._scans[0].url == url:
                self._scans[0] = record
            else:
                self._scans.appendleft(record)

        return record

    def list_recent(self, limit: int = 25) -> list[dict]:
        with self._lock:
            return [asdict(r) for r in list(self._scans)[:limit]]

    def get_latest(self) -> dict | None:
        with self._lock:
            if self._scans:
                return asdict(self._scans[0])
            return None


RECENT_SCANS = RecentScansStore()
