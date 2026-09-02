from census.checks import (
    check_dkim,
    check_dmarc,
    check_dnssec,
    check_domain,
    check_mta_sts,
    check_mx,
    check_spf,
    count_spf_lookups,
)

D = "district.example"


def test_spf_lookup_count_follows_includes_and_redirect(fake_resolver):
    r = fake_resolver({
        (D, "TXT"): ["v=spf1 a mx include:_spf.google.com include:vendor.example -all"],
        ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"],
        ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:1.1.1.0/24 ~all"],
        ("_netblocks2.google.com", "TXT"): ["v=spf1 ip6:2001::/32 ~all"],
        ("vendor.example", "TXT"): ["v=spf1 redirect=_spf.vendor.example"],
        ("_spf.vendor.example", "TXT"): ["v=spf1 mx -all"],
    })
    s = check_spf(D, r)
    # a, mx, include:google, include:vendor (4) + google's 2 includes (2) + redirect (1) + mx (1)
    assert s["lookup_count"] == 8
    assert not s["lookup_limit_exceeded"] and not s["include_loop"]
    assert s["void_lookups"] == 0
    assert s["queried_at"] == "2026-01-01T00:00:00+00:00"


def test_spf_over_limit(fake_resolver):
    incs = " ".join(f"include:i{n}.example" for n in range(6))
    r = fake_resolver({
        (D, "TXT"): [f"v=spf1 {incs} -all"],
        **{(f"i{n}.example", "TXT"): ["v=spf1 a mx -all"] for n in range(6)},
    })
    s = check_spf(D, r)
    assert s["lookup_count"] > 10 and s["lookup_limit_exceeded"]


def test_spf_include_loop_and_void(fake_resolver):
    r = fake_resolver({
        (D, "TXT"): ["v=spf1 include:loop.example include:nothing.example -all"],
        ("loop.example", "TXT"): [f"v=spf1 include:{D} -all"],
    })
    s = count_spf_lookups(D, r, first_record="v=spf1 include:loop.example include:nothing.example -all")
    assert s["include_loop"] is True
    assert s["void_lookups"] == 1  # nothing.example is NXDOMAIN


def test_spf_walker_query_cap(fake_resolver):
    """A pathological record must not make us issue unbounded queries."""
    chain = {(D, "TXT"): ["v=spf1 include:c0.example -all"]}
    for n in range(100):
        chain[(f"c{n}.example", "TXT")] = [f"v=spf1 include:c{n + 1}.example -all"]
    r = fake_resolver(chain)
    s = check_spf(D, r)
    assert s["lookup_limit_exceeded"]
    assert len(r.calls) < 40


def test_spf_absent(fake_resolver):
    s = check_spf(D, fake_resolver({(D, "TXT"): ["google-site-verification=x"]}))
    assert not s["present"] and s["lookup_count"] == 0 and s["dns_status"] == "NOERROR"


def test_spf_dns_error(fake_resolver):
    s = check_spf(D, fake_resolver({(D, "TXT"): "ERROR"}))
    assert s["error"] == "timeout" and not s["present"]


def test_dmarc_lookup_uses_underscore_name(fake_resolver):
    r = fake_resolver({(f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:r@x.y"]})
    d = check_dmarc(D, r)
    assert d["policy"] == "quarantine" and d["rua"]
    assert r.calls == [(f"_dmarc.{D}", "TXT")]


def test_dkim_found(fake_resolver):
    r = fake_resolver({
        (f"google._domainkey.{D}", "TXT"): ["v=DKIM1; k=rsa; p=ABC"],
        (f"selector1._domainkey.{D}", "TXT"): ["v=DKIM1; p="],
        (f"_domainkey.{D}", "TXT"): [],
    })
    k = check_dkim(D, r)
    assert k["status"] == "found"
    assert k["selectors_found"] == ["google"] and k["selectors_revoked"] == ["selector1"]
    assert k["domainkey_subtree_exists"] is True


def test_dkim_not_found_vs_unknown(fake_resolver):
    assert check_dkim(D, fake_resolver({}))["status"] == "not_found"
    r = fake_resolver({(f"google._domainkey.{D}", "TXT"): "ERROR"})
    assert check_dkim(D, r)["status"] == "unknown"


def test_mta_sts_never_fetches_http(fake_resolver):
    r = fake_resolver({
        (f"_mta-sts.{D}", "TXT"): ["v=STSv1; id=1"],
        (f"_smtp._tls.{D}", "TXT"): ["v=TLSRPTv1; rua=mailto:t@x.y"],
    })
    m = check_mta_sts(D, r)
    assert m["present"] and m["mode"] is None and m["tlsrpt"]["present"]
    assert all(t == "TXT" for _, t in r.calls)


def test_mx(fake_resolver):
    m = check_mx(D, fake_resolver({(D, "MX"): ["aspmx.l.google.com.", "alt1.aspmx.l.google.com."]}))
    assert m["provider"] == "Google Workspace" and m["mx_hosts"][0] == "aspmx.l.google.com"


def test_dnssec_states(fake_resolver):
    signed = fake_resolver({(D, "DS"): ["12345 13 2 ABCD"], (D, "DNSKEY"): ["257 3 13 KEY"]}, ad={D})
    s = check_dnssec(D, signed)
    assert s["signed"] and s["validated"] and s["ad_flag"]
    unsigned = check_dnssec(D, fake_resolver({(D, "DS"): [], (D, "DNSKEY"): []}))
    assert not unsigned["signed"] and not unsigned["validated"]
    partial = check_dnssec(D, fake_resolver({(D, "DS"): [], (D, "DNSKEY"): ["257 3 13 KEY"]}))
    assert partial["dnskey_present"] and not partial["signed"]


def test_check_domain_shape_and_only_passive_query_types(fake_resolver):
    r = fake_resolver({})
    out = check_domain(D, r)
    assert set(out) == {"spf", "dmarc", "dkim", "mta_sts", "mx", "dnssec"}
    assert {t for _, t in r.calls} <= {"TXT", "MX", "DS", "DNSKEY"}
    assert all(n == D or n.endswith("." + D) for n, _ in r.calls)


def test_broken_dnssec_denial_of_existence_is_reported_not_fatal(fake_resolver):
    """Signed zone, but nonexistent names only resolve with CD (as seen on some
    registrar DNS). DKIM must be not_found (not unknown), and DNSSEC must flag it."""
    r = fake_resolver({
        (D, "TXT"): ["v=spf1 -all"],
        (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=reject"],
        (D, "DS"): ["1 13 2 AB"], (D, "DNSKEY"): ["257 3 13 K"],
        (D, "MX"): ["mail.district.example"],
        **{(f"{s}._domainkey.{D}", "TXT"): "SERVFAIL_CD" for s in
           ["google", "selector1", "selector2", "default", "k1", "s1", "s2"]},
        (f"_domainkey.{D}", "TXT"): "SERVFAIL_CD",
        (f"_mta-sts.{D}", "TXT"): "SERVFAIL_CD",
        (f"_smtp._tls.{D}", "TXT"): "SERVFAIL_CD",
    }, ad={D})
    out = check_domain(D, r)
    assert out["dkim"]["status"] == "not_found" and out["dkim"]["validation_failed"]
    assert out["mta_sts"]["present"] is False and out["mta_sts"]["error"] is None
    assert out["dnssec"]["signed"] and out["dnssec"]["nonexistence_proof_broken"]
    assert out["spf"]["validation_failed"] is False


def test_unsigned_zone_never_flags_broken_proof(fake_resolver):
    out = check_domain(D, fake_resolver({(f"_mta-sts.{D}", "TXT"): "SERVFAIL_CD"}))
    assert out["dnssec"]["any_validation_failed"] and not out["dnssec"]["nonexistence_proof_broken"]
