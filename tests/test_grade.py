"""One case per RUBRIC.md row plus each cap. Keep in sync with RUBRIC.md."""

import pytest

from census.grade import grade, spf_is_valid


def spf(all_q="-", count=1, lookups=3, present=True, **kw):
    return {"present": present, "record_count": count, "all_qualifier": all_q,
            "lookup_count": lookups, "lookup_limit_exceeded": lookups > 10, "include_loop": False, **kw}


def dmarc(p="reject", sp=None, pct=100, rua=True, valid=True, present=True):
    return {"present": present, "valid": valid, "policy": p, "subdomain_policy": sp or p,
            "pct": pct, "rua": rua, "parse_errors": [] if valid else ["missing p"]}


@pytest.mark.parametrize(
    "s, d, expected",
    [
        # A
        (spf("-"), dmarc("reject"), "A"),
        (spf("~"), dmarc("reject", rua=False), "A"),  # ~all is valid SPF; rua not required at reject
        # B
        (spf("-"), dmarc("reject", pct=50), "B"),
        (spf("-"), dmarc("reject", sp="none"), "B"),
        (spf("-"), dmarc("quarantine"), "B"),
        # C
        (spf("-"), dmarc("quarantine", pct=20), "C"),
        (spf("-"), dmarc("none", rua=True), "C"),
        # D
        (spf("-"), dmarc("none", rua=False), "D"),
        (spf("+"), dmarc("reject"), "D"),  # broken SPF caps at D
        (spf("?"), dmarc("reject"), "D"),
        (spf(None), dmarc("reject"), "D"),  # no all mechanism
        (spf(present=False), dmarc("reject"), "D"),
        (spf("-", count=2), dmarc("reject"), "D"),
        (spf("-", lookups=11), dmarc("quarantine"), "D"),
        # F
        (spf("-"), dmarc(present=False, valid=False), "F"),
        (spf("-"), dmarc(valid=False), "F"),
    ],
)
def test_rubric_rows(s, d, expected):
    g, reasons = grade(s, d)
    assert g == expected, reasons
    assert reasons  # every grade is explained


def test_na_cases():
    assert grade(spf(), dmarc(), "consumer_provider")[0] == "N/A"
    assert grade(spf(), dmarc(), "no_domain")[0] == "N/A"
    assert grade({**spf(), "error": "timeout"}, dmarc())[0] == "N/A"


def test_spf_is_valid_reports_every_problem():
    ok, problems = spf_is_valid(spf("+", count=2, lookups=12))
    assert not ok and len(problems) == 3


def test_dkim_does_not_affect_grade():
    """Rubric decision: DKIM is recorded, not scored. grade() does not even take it."""
    assert grade(spf("-"), dmarc("reject"))[0] == "A"
