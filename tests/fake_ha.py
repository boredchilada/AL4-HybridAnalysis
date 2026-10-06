"""Offline stand-in for HybridAnalysisClient, fed by tests/fixtures/ha/<sha256>.json.

Each fixture holds what Hybrid Analysis would return for one file: ``reports`` (GET /search/hash),
``summaries`` (GET /report/<id>/summary by report ID) and ``overview`` (GET /overview/<sha256>).
Files without a fixture are unknown to Hybrid Analysis. The fake never touches the network and
refuses uploads.
"""

import json
from pathlib import Path

import hybridanalysis.service

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ha"


class FakeClient:
    def __init__(self, *_: object, **__: object) -> None:
        self._data: dict = {}

    def search_hash(self, sha256: str) -> list[dict]:
        path = FIXTURES / f"{sha256}.json"
        self._data = json.loads(path.read_text()) if path.exists() else {}
        return self._data.get("reports", [])

    def summary(self, report_id: str) -> dict:
        return self._data["summaries"][report_id]

    def overview(self, sha256: str) -> dict:
        return self._data.get("overview", {})

    def submit(self, *_: object) -> dict:
        raise AssertionError("tests must not upload through the shared fake")


def install() -> None:
    """Replace the client the service builds, for pytest and for scripts/gentests.py."""
    hybridanalysis.service.HybridAnalysisClient = FakeClient  # type: ignore[misc]
