"""Pure parsers for email-authentication DNS records.

Nothing in this module touches the network. Every function takes strings (the TXT/MX
answers a resolver already returned) and returns plain dicts, so the parsers can be unit
tested with fake records and reused by any caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- SPF

# Mechanisms that cost a DNS lookup under RFC 7208 §4.6.4. "include" and "redirect" are
# counted in the recursive walker in checks.py because they also need to be followed.
SPF_LOOKUP_MECHANISMS = {"a", "mx", "ptr", "exists", "include"}
SPF_QUALIFIERS = {"+", "-", "~", "?"}
SPF_LOOKUP_LIMIT = 10


@dataclass
class SpfRecord:
    raw: str
    terms: list[str] = field(default_factory=list)
    all_qualifier: str | None = None  # "+", "-", "~", "?" or None if no `all`
    includes: list[str] = field(default_factory=list)
    redirect: str | None = None
    lookup_terms: int = 0  # a/mx/ptr/exists/include terms in THIS record only
    parse_errors: list[str] = field(default_factory=list)


def is_spf(txt: str) -> bool:
    return txt.strip().lower().startswith("v=spf1")


def parse_spf_record(txt: str) -> SpfRecord:
    """Parse a single ``v=spf1`` TXT string into its terms."""
    rec = SpfRecord(raw=txt)
    terms = txt.strip().split()
    if not terms or terms[0].lower() != "v=spf1":
        rec.parse_errors.append("missing v=spf1 prefix")
        return rec
    for term in terms[1:]:
        low = term.lower()
        qualifier = "+"
        body = low
        if body[0] in SPF_QUALIFIERS:
            qualifier, body = body[0], body[1:]
        rec.terms.append(term)

        # modifiers: name=value
        if "=" in body and ":" not in body.split("=", 1)[0]:
            name, value = body.split("=", 1)
            if name == "redirect":
                rec.redirect = value
            # exp= and unknown modifiers do not cost lookups (exp is evaluated lazily)
            continue

        name = body.split(":", 1)[0].split("/", 1)[0]
        if name == "all":
            if rec.all_qualifier is None:
                rec.all_qualifier = qualifier
            continue
        if name in SPF_LOOKUP_MECHANISMS:
            rec.lookup_terms += 1
            if name == "include":
                if ":" in body:
                    rec.includes.append(body.split(":", 1)[1])
                else:
                    rec.parse_errors.append(f"include without domain: {term}")
        elif name not in {"ip4", "ip6"}:
            rec.parse_errors.append(f"unknown term: {term}")
    return rec


def summarize_spf(txt_records: list[str]) -> dict:
    """Summarise the SPF situation at one name from its TXT records.

    Lookup counting across includes needs DNS, so it lives in checks.py; this only
    reports what can be known from the apex record(s) themselves.
    """
    spf_records = [r for r in txt_records if is_spf(r)]
    out: dict = {
        "present": bool(spf_records),
        "record_count": len(spf_records),
        "records": spf_records,
        "all_qualifier": None,
        "all_label": None,
        "includes": [],
        "redirect": None,
        "parse_errors": [],
    }
    if not spf_records:
        return out
    if len(spf_records) > 1:
        # RFC 7208 §3.2: more than one record is a permerror. We still parse the first
        # so the rest of the report is informative.
        out["parse_errors"].append("multiple SPF records (permerror)")
    rec = parse_spf_record(spf_records[0])
    out["all_qualifier"] = rec.all_qualifier
    out["all_label"] = {
        "-": "fail (-all)",
        "~": "softfail (~all)",
        "?": "neutral (?all)",
        "+": "pass (+all)",
        None: "no all mechanism",
    }[rec.all_qualifier]
    out["includes"] = rec.includes
    out["redirect"] = rec.redirect
    out["parse_errors"].extend(rec.parse_errors)
    return out


# ------------------------------------------------------------------------- DMARC

DMARC_POLICIES = {"none", "quarantine", "reject"}


def is_dmarc(txt: str) -> bool:
    return txt.strip().lower().startswith("v=dmarc1")


def parse_tag_value(txt: str) -> dict[str, str]:
    """Parse ``k=v; k2=v2`` records (DMARC, DKIM, MTA-STS, TLS-RPT all use this shape)."""
    tags: dict[str, str] = {}
    for part in txt.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


def summarize_dmarc(txt_records: list[str]) -> dict:
    dmarc_records = [r for r in txt_records if is_dmarc(r)]
    out: dict = {
        "present": bool(dmarc_records),
        "record_count": len(dmarc_records),
        "records": dmarc_records,
        "valid": False,
        "policy": None,
        "subdomain_policy": None,
        "pct": None,
        "rua": False,
        "ruf": False,
        "adkim": None,
        "aspf": None,
        "parse_errors": [],
    }
    if not dmarc_records:
        return out
    if len(dmarc_records) > 1:
        # RFC 7489 §6.6.3: multiple records -> DMARC processing is discontinued.
        out["parse_errors"].append("multiple DMARC records")
        return out
    tags = parse_tag_value(dmarc_records[0])
    policy = tags.get("p", "").lower()
    if policy not in DMARC_POLICIES:
        out["parse_errors"].append(f"missing or invalid p= tag: {policy!r}")
        return out
    out["policy"] = policy
    sp = tags.get("sp", "").lower()
    if sp and sp not in DMARC_POLICIES:
        out["parse_errors"].append(f"invalid sp= tag: {sp!r}")
        sp = ""
    out["subdomain_policy"] = sp or policy  # sp defaults to p
    out["subdomain_policy_explicit"] = bool(sp)
    pct_raw = tags.get("pct", "100")
    try:
        pct = int(pct_raw)
        if not 0 <= pct <= 100:
            raise ValueError
    except ValueError:
        out["parse_errors"].append(f"invalid pct= tag: {pct_raw!r}")
        pct = 100
    out["pct"] = pct
    out["rua"] = bool(tags.get("rua", "").strip())
    out["ruf"] = bool(tags.get("ruf", "").strip())
    out["adkim"] = (tags.get("adkim") or "r").lower()
    out["aspf"] = (tags.get("aspf") or "r").lower()
    out["valid"] = True
    return out


# -------------------------------------------------------------------------- DKIM


def summarize_dkim_record(txt_records: list[str]) -> dict:
    """Classify the TXT answer at ``<selector>._domainkey.<domain>``."""
    if not txt_records:
        return {"exists": False, "looks_like_key": False, "revoked": False}
    joined = txt_records[0]
    tags = parse_tag_value(joined)
    has_p = "p" in tags
    looks_like_key = tags.get("v", "").upper() == "DKIM1" or has_p
    revoked = has_p and tags["p"] == ""
    return {
        "exists": True,
        "looks_like_key": looks_like_key,
        "revoked": revoked,
        "key_type": tags.get("k", "rsa") if looks_like_key else None,
    }


# ----------------------------------------------------------------------- MTA-STS


def summarize_mta_sts(txt_records: list[str]) -> dict:
    """Parse ``_mta-sts.<domain>`` TXT. Mode lives in the HTTPS policy file, which we
    deliberately do not fetch (that would contact district infrastructure), so only the
    DNS-visible fields are reported."""
    recs = [r for r in txt_records if r.strip().lower().startswith("v=stsv1")]
    out = {"present": bool(recs), "record_count": len(recs), "id": None, "parse_errors": []}
    if len(recs) > 1:
        out["parse_errors"].append("multiple MTA-STS records")
    if recs:
        out["id"] = parse_tag_value(recs[0]).get("id")
    return out


def summarize_tlsrpt(txt_records: list[str]) -> dict:
    recs = [r for r in txt_records if r.strip().lower().startswith("v=tlsrptv1")]
    return {"present": bool(recs), "rua": bool(recs and parse_tag_value(recs[0]).get("rua"))}


# ---------------------------------------------------------------------------- MX

# Ordered: first suffix match wins. Suffix match is on the MX hostname (lowercased,
# trailing dot stripped).
MX_PROVIDERS: list[tuple[str, tuple[str, ...]]] = [
    ("Google Workspace", (".google.com", ".googlemail.com")),
    ("Microsoft 365", (".mail.protection.outlook.com", ".outlook.com", ".mail.eo.outlook.com")),
    ("Proofpoint", (".pphosted.com", ".ppe-hosted.com")),
    ("Mimecast", (".mimecast.com", ".mimecast-offshore.com")),
    ("Barracuda", (".barracudanetworks.com",)),
    ("Cisco Secure Email", (".iphmx.com",)),
    ("Sophos", (".sophos.com",)),
    ("Zoho", (".zoho.com",)),
    ("GoDaddy / Secureserver", (".secureserver.net",)),
    ("Rackspace", (".emailsrvr.com",)),
    ("Fortinet", (".fortimail.com",)),
]


def classify_mx(mx_hosts: list[str], domain: str) -> dict:
    """Classify a domain's mail provider from its MX hostnames only."""
    hosts = [h.lower().rstrip(".") for h in mx_hosts]
    if not hosts:
        return {"provider": "no MX", "self_hosted": False}
    if hosts == [""]:
        # RFC 7505 null MX: "0 ." means the domain accepts no mail.
        return {"provider": "null MX (no mail)", "self_hosted": False}
    found: list[str] = []
    for host in hosts:
        for provider, suffixes in MX_PROVIDERS:
            if any(host.endswith(s) or host == s.lstrip(".") for s in suffixes):
                if provider not in found:
                    found.append(provider)
                break
    domain = domain.lower().rstrip(".")
    self_hosted = any(h == domain or h.endswith("." + domain) for h in hosts)
    if found:
        provider = found[0] if len(found) == 1 else " + ".join(found)
    elif self_hosted:
        provider = "self-hosted"
    else:
        provider = "other"
    return {"provider": provider, "self_hosted": self_hosted}


# -------------------------------------------------------------------- utilities

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.lower().rstrip(".")))
