"""Per-domain checks. Each function takes a ``resolve(name, rtype) -> Answer`` callable
and returns a plain dict, so the same code runs against the real cached resolver and
against a dict-backed fake in tests. Nothing here opens a socket itself."""

from __future__ import annotations

from typing import Callable

from .dns_client import Answer
from .parsers import (
    SPF_LOOKUP_LIMIT,
    classify_mx,
    is_spf,
    parse_spf_record,
    summarize_dkim_record,
    summarize_dmarc,
    summarize_mta_sts,
    summarize_spf,
    summarize_tlsrpt,
)

Resolve = Callable[[str, str], Answer]

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "s2"]
SPF_VOID_LOOKUP_LIMIT = 2
# Hard stop for the include walker so a pathological record cannot make us issue an
# unbounded number of queries. Anything past 10 is already a permerror.
SPF_WALK_QUERY_CAP = 25


def _base(ans: Answer) -> dict:
    """Fields every check carries: when it was looked up and whether the lookup failed."""
    return {"queried_at": ans.queried_at, "dns_status": ans.status, "error": ans.error,
            "validation_failed": ans.cd_fallback}


# ----------------------------------------------------------------------------- SPF


def count_spf_lookups(domain: str, resolve: Resolve, first_record: str | None = None) -> dict:
    """Walk include:/redirect= chains and count DNS-costing terms (RFC 7208 §4.6.4).

    Returns lookup_count, void_lookups, whether the 10-lookup limit was exceeded, and
    whether an include loop was seen. The walk stops early once the count is hopeless
    so a bad record cannot trigger many extra queries.
    """
    state = {"count": 0, "void": 0, "loop": False, "queries": 0, "chain": []}
    visited: set[str] = set()

    def walk(name: str, record: str | None) -> None:
        name = name.lower().rstrip(".")
        if name in visited:
            state["loop"] = True
            return
        visited.add(name)
        if record is None:
            if state["queries"] >= SPF_WALK_QUERY_CAP:
                return
            state["queries"] += 1
            ans = resolve(name, "TXT")
            spf_recs = [r for r in ans.records if is_spf(r)]
            if not spf_recs:
                # include: of a name with no SPF is a "void lookup"; it still cost one.
                state["void"] += 1
                return
            record = spf_recs[0]
        rec = parse_spf_record(record)
        state["count"] += rec.lookup_terms
        state["chain"].append(name)
        for inc in rec.includes:
            if state["count"] > SPF_LOOKUP_LIMIT:
                return
            walk(inc, None)
        if rec.redirect:
            state["count"] += 1
            if state["count"] <= SPF_LOOKUP_LIMIT:
                walk(rec.redirect, None)

    walk(domain, first_record)
    return {
        "lookup_count": state["count"],
        "void_lookups": state["void"],
        "lookup_limit_exceeded": state["count"] > SPF_LOOKUP_LIMIT
        or state["void"] > SPF_VOID_LOOKUP_LIMIT,
        "include_loop": state["loop"],
        "include_chain": state["chain"],
    }


def check_spf(domain: str, resolve: Resolve) -> dict:
    ans = resolve(domain, "TXT")
    out = {**_base(ans), **summarize_spf(ans.records)}
    if out["present"]:
        out.update(count_spf_lookups(domain, resolve, first_record=out["records"][0]))
    else:
        out.update(
            {"lookup_count": 0, "void_lookups": 0, "lookup_limit_exceeded": False,
             "include_loop": False, "include_chain": []}
        )
    return out


# --------------------------------------------------------------------------- DMARC


def check_dmarc(domain: str, resolve: Resolve) -> dict:
    ans = resolve(f"_dmarc.{domain}", "TXT")
    return {**_base(ans), **summarize_dmarc(ans.records)}


# ---------------------------------------------------------------------------- DKIM


def check_dkim(domain: str, resolve: Resolve, selectors: list[str] | None = None) -> dict:
    """Probe common selectors. Can prove DKIM is *present*, never that it is absent."""
    selectors = selectors or DKIM_SELECTORS
    found: dict[str, dict] = {}
    errors = 0
    validation_failed = False
    queried_at = ""
    for sel in selectors:
        ans = resolve(f"{sel}._domainkey.{domain}", "TXT")
        queried_at = queried_at or ans.queried_at
        validation_failed = validation_failed or ans.cd_fallback
        if ans.status == "ERROR":
            errors += 1
            continue
        info = summarize_dkim_record(ans.records)
        if info["exists"]:
            found[sel] = info
    # Weak "configured at all" signal: NXDOMAIN at _domainkey means no selector of any
    # name exists under it; NOERROR/NOANSWER means the subtree exists.
    parent = resolve(f"_domainkey.{domain}", "TXT")
    key_selectors = [s for s, i in found.items() if i["looks_like_key"] and not i["revoked"]]
    if key_selectors:
        status = "found"
    elif errors or parent.status == "ERROR":
        status = "unknown"
    else:
        status = "not_found"
    return {
        "queried_at": queried_at,
        "error": None if not errors else f"{errors} selector lookups failed",
        "status": status,
        "selectors_probed": selectors,
        "selectors_found": key_selectors,
        "selectors_revoked": [s for s, i in found.items() if i["revoked"]],
        "domainkey_subtree_exists": parent.status in ("NOERROR", "NOANSWER"),
        "validation_failed": validation_failed or parent.cd_fallback,
    }


# ------------------------------------------------------------------------- MTA-STS


def check_mta_sts(domain: str, resolve: Resolve) -> dict:
    ans = resolve(f"_mta-sts.{domain}", "TXT")
    tls = resolve(f"_smtp._tls.{domain}", "TXT")
    out = {**_base(ans), **summarize_mta_sts(ans.records)}
    out["validation_failed"] = ans.cd_fallback or tls.cd_fallback
    out["tlsrpt"] = summarize_tlsrpt(tls.records)
    # The policy file (and its mode) lives at https://mta-sts.<domain>/.well-known/...
    # Fetching it would contact the district's web infrastructure, so we do not.
    out["mode"] = None
    out["mode_note"] = "mode lives in the HTTPS policy file, not fetched (passive DNS only)"
    return out


# ------------------------------------------------------------------------------ MX


def check_mx(domain: str, resolve: Resolve) -> dict:
    ans = resolve(domain, "MX")
    hosts = [h.rstrip(".") for h in ans.records]
    out = {**_base(ans), "mx_hosts": hosts}
    out.update(classify_mx(hosts, domain))
    return out


# -------------------------------------------------------------------------- DNSSEC


def check_dnssec(domain: str, resolve: Resolve) -> dict:
    """Signed = DS at the parent AND DNSKEY at the zone; validated = the public resolver
    set the AD flag. Both are ordinary resolver queries."""
    ds = resolve(domain, "DS")
    dnskey = resolve(domain, "DNSKEY")
    ds_present = ds.ok
    dnskey_present = dnskey.ok
    return {
        "queried_at": ds.queried_at,
        "error": ds.error or dnskey.error,
        "ds_present": ds_present,
        "dnskey_present": dnskey_present,
        "ad_flag": dnskey.ad or ds.ad,
        "signed": ds_present and dnskey_present,
        "validated": dnskey.ad,
        "validation_failed": ds.cd_fallback or dnskey.cd_fallback,
        # filled in by check_domain once every lookup for the domain has run
        "nonexistence_proof_broken": False,
    }


# ------------------------------------------------------------------------- bundle


def check_domain(domain: str, resolve: Resolve, selectors: list[str] | None = None) -> dict:
    out = {
        "spf": check_spf(domain, resolve),
        "dmarc": check_dmarc(domain, resolve),
        "dkim": check_dkim(domain, resolve, selectors),
        "mta_sts": check_mta_sts(domain, resolve),
        "mx": check_mx(domain, resolve),
        "dnssec": check_dnssec(domain, resolve),
    }
    # A signed zone whose answers only validate with checking disabled has broken
    # DNSSEC for at least some names (in practice: the proof that a name does not
    # exist). Strict validators will SERVFAIL there, e.g. on DKIM selector lookups.
    any_failed = any(c.get("validation_failed") for c in out.values())
    out["dnssec"]["nonexistence_proof_broken"] = bool(out["dnssec"]["signed"] and any_failed)
    out["dnssec"]["any_validation_failed"] = any_failed
    return out
