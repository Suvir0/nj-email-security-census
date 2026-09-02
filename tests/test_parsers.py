import pytest

from census.parsers import (
    classify_mx,
    looks_like_domain,
    parse_spf_record,
    parse_tag_value,
    summarize_dkim_record,
    summarize_dmarc,
    summarize_mta_sts,
    summarize_spf,
    summarize_tlsrpt,
)

# ------------------------------------------------------------------------------ SPF


@pytest.mark.parametrize(
    "record, qualifier",
    [
        ("v=spf1 include:_spf.google.com -all", "-"),
        ("v=spf1 include:_spf.google.com ~all", "~"),
        ("v=spf1 include:_spf.google.com ?all", "?"),
        ("v=spf1 include:_spf.google.com +all", "+"),
        ("v=spf1 include:_spf.google.com all", "+"),  # bare `all` defaults to +
        ("v=spf1 include:_spf.google.com", None),
        ("V=SPF1 IP4:1.2.3.4 -ALL", "-"),  # case-insensitive
    ],
)
def test_spf_all_qualifier(record, qualifier):
    assert parse_spf_record(record).all_qualifier == qualifier


def test_spf_counts_lookup_terms_and_collects_includes():
    rec = parse_spf_record("v=spf1 a mx ip4:10.0.0.0/8 include:a.example include:b.example exists:%{i}.x ptr -all")
    assert rec.lookup_terms == 6  # a, mx, include, include, exists, ptr
    assert rec.includes == ["a.example", "b.example"]
    assert rec.parse_errors == []


def test_spf_redirect_and_exp():
    rec = parse_spf_record("v=spf1 exp=explain.example redirect=_spf.example.org")
    assert rec.redirect == "_spf.example.org"
    assert rec.lookup_terms == 0  # exp and redirect are not counted here; walker adds redirect


def test_spf_a_with_domain_and_cidr_counts_once():
    rec = parse_spf_record("v=spf1 a:mail.example.org/24 mx:example.org -all")
    assert rec.lookup_terms == 2


def test_summarize_spf_ignores_non_spf_txt_and_flags_multiple():
    txts = ["google-site-verification=abc", "v=spf1 -all", "v=spf1 ~all"]
    s = summarize_spf(txts)
    assert s["present"] and s["record_count"] == 2
    assert "multiple SPF records (permerror)" in s["parse_errors"]
    assert s["all_qualifier"] == "-"


def test_summarize_spf_absent():
    s = summarize_spf(["something-else=1"])
    assert s == {
        "present": False, "record_count": 0, "records": [], "all_qualifier": None,
        "all_label": None, "includes": [], "redirect": None, "parse_errors": [],
    }


# ---------------------------------------------------------------------------- DMARC


def test_dmarc_full_record():
    d = summarize_dmarc(["v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:x@example.org; ruf=mailto:y@example.org; adkim=s"])
    assert d["valid"] and d["policy"] == "reject"
    assert d["subdomain_policy"] == "quarantine" and d["subdomain_policy_explicit"]
    assert d["pct"] == 50 and d["rua"] and d["ruf"]
    assert d["adkim"] == "s" and d["aspf"] == "r"


def test_dmarc_minimal_record_defaults():
    d = summarize_dmarc(["v=DMARC1; p=none"])
    assert d["valid"] and d["policy"] == "none"
    assert d["subdomain_policy"] == "none" and not d["subdomain_policy_explicit"]
    assert d["pct"] == 100 and d["rua"] is False


@pytest.mark.parametrize(
    "record",
    ["v=DMARC1; pct=100", "v=DMARC1; p=bogus", "v=DMARC1", "p=reject"],
)
def test_dmarc_invalid_or_absent(record):
    d = summarize_dmarc([record])
    assert not d["valid"]
    if record.lower().startswith("v=dmarc1"):
        assert d["present"] and d["parse_errors"]
    else:
        assert not d["present"]


def test_dmarc_multiple_records_invalid():
    d = summarize_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert d["present"] and not d["valid"] and d["record_count"] == 2


def test_dmarc_bad_pct_falls_back_to_100_with_error():
    d = summarize_dmarc(["v=DMARC1; p=quarantine; pct=abc"])
    assert d["valid"] and d["pct"] == 100 and d["parse_errors"]


def test_dmarc_case_and_whitespace_tolerant():
    d = summarize_dmarc(["V=DMARC1 ;  P=Reject;RUA = mailto:a@b.c"])
    assert d["valid"] and d["policy"] == "reject" and d["rua"]


# ----------------------------------------------------------------------------- DKIM


def test_dkim_record_variants():
    assert summarize_dkim_record([])["exists"] is False
    ok = summarize_dkim_record(["v=DKIM1; k=rsa; p=MIGfMA0GCSq"])
    assert ok["exists"] and ok["looks_like_key"] and not ok["revoked"]
    revoked = summarize_dkim_record(["v=DKIM1; p="])
    assert revoked["revoked"]
    junk = summarize_dkim_record(["hello"])
    assert junk["exists"] and not junk["looks_like_key"]


# -------------------------------------------------------------------------- MTA-STS


def test_mta_sts_and_tlsrpt():
    s = summarize_mta_sts(["v=STSv1; id=20240101T000000"])
    assert s["present"] and s["id"] == "20240101T000000"
    assert summarize_mta_sts(["v=spf1 -all"])["present"] is False
    t = summarize_tlsrpt(["v=TLSRPTv1; rua=mailto:tls@example.org"])
    assert t["present"] and t["rua"]


def test_parse_tag_value():
    assert parse_tag_value(" a=1; B = two ;;c=x=y") == {"a": "1", "b": "two", "c": "x=y"}


# ------------------------------------------------------------------------------- MX


@pytest.mark.parametrize(
    "hosts, provider",
    [
        (["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "Google Workspace"),
        (["example-org.mail.protection.outlook.com"], "Microsoft 365"),
        (["mxa-001.pphosted.com", "mxb-001.pphosted.com"], "Proofpoint"),
        (["us-smtp-inbound-1.mimecast.com"], "Mimecast"),
        (["d123.a.barracudanetworks.com"], "Barracuda"),
        (["mail.example.org"], "self-hosted"),
        (["mx.somevendor.net"], "other"),
        ([], "no MX"),
        ([""], "null MX (no mail)"),
        (["aspmx.l.google.com", "mx.pphosted.com"], "Google Workspace + Proofpoint"),
    ],
)
def test_classify_mx(hosts, provider):
    assert classify_mx(hosts, "example.org")["provider"] == provider


def test_classify_mx_self_hosted_flag():
    assert classify_mx(["MAIL.EXAMPLE.ORG."], "example.org")["self_hosted"] is True
    assert classify_mx(["aspmx.l.google.com"], "example.org")["self_hosted"] is False


# ------------------------------------------------------------------------ utilities


@pytest.mark.parametrize("v, ok", [("eht.k12.nj.us", True), ("a.bc", True), ("a.b", False), ("Rose", False), ("n/a", False), ("", False)])
def test_looks_like_domain(v, ok):
    assert looks_like_domain(v) is ok
