"""Shared fixtures: a dict-backed fake resolver so no test touches the network."""

from __future__ import annotations

import pytest

from census.dns_client import Answer

FAKE_TIME = "2026-01-01T00:00:00+00:00"


class FakeResolver:
    """``records`` maps (name, rtype) -> list[str] | "NXDOMAIN" | "ERROR" | "SERVFAIL_CD".

    "SERVFAIL_CD" models a validating resolver returning SERVFAIL and the CD retry
    returning an empty answer (broken DNSSEC denial of existence).

    Unknown names return NXDOMAIN, like a real resolver would for a name that does not
    exist. A name mapped to an empty list returns NOANSWER (name exists, no records of
    that type).
    """

    def __init__(self, records: dict[tuple[str, str], list[str] | str], ad: set[str] = frozenset()):
        self.records = {(n.lower(), t.upper()): v for (n, t), v in records.items()}
        self.ad = {n.lower() for n in ad}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, name: str, rtype: str) -> Answer:
        name, rtype = name.lower().rstrip("."), rtype.upper()
        self.calls.append((name, rtype))
        v = self.records.get((name, rtype), "NXDOMAIN")
        if v == "NXDOMAIN":
            return Answer(name, rtype, "NXDOMAIN", [], False, FAKE_TIME)
        if v == "ERROR":
            return Answer(name, rtype, "ERROR", [], False, FAKE_TIME, error="timeout")
        if v == "SERVFAIL_CD":
            return Answer(name, rtype, "NOANSWER", [], False, FAKE_TIME, cd_fallback=True)
        status = "NOERROR" if v else "NOANSWER"
        return Answer(name, rtype, status, list(v), name in self.ad, FAKE_TIME)


@pytest.fixture
def fake_resolver():
    return FakeResolver
