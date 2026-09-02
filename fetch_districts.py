#!/usr/bin/env python3
"""Step 1: fetch the NJDOE public school district directory and derive districts.csv.

Source: the "Public School Districts" download linked from the NJ School Directory
(https://homeroom6.doe.nj.gov/directory/). This is the only HTTP request the whole
pipeline makes, and it goes to NJDOE, not to any district.

What we keep per district: identity (county, code, name, type), the website domain,
and the *domain part* of the listed superintendent / business-administrator email.
The email addresses themselves are never written out.

Domains are never guessed. If the directory does not give us a usable domain the field is
left blank and flagged.
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from collections import Counter
from pathlib import Path

import requests
import tldextract

from census.parsers import looks_like_domain

SOURCE_URL = "https://homeroom4.doe.nj.gov/public/districtpublicschools/download/"
USER_AGENT = "NJ-K12-Email-Security-Census/0.1 (research; passive DNS survey)"
PREAMBLE_LINES = 3

# Consumer mailbox providers: a district whose listed contact uses one of these has no
# domain of its own to assess.
CONSUMER_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "aol.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "icloud.com", "me.com", "mac.com", "comcast.net", "verizon.net",
    "optonline.net", "optimum.net", "att.net", "sbcglobal.net", "protonmail.com", "proton.me",
}
# Website hosts that are shared platforms, so their registrable domain is not the district's.
THIRD_PARTY_HOSTS = {
    "google.com", "weebly.com", "wixsite.com", "wix.com", "squarespace.com", "godaddysites.com",
    "wordpress.com", "blogspot.com", "facebook.com", "sites.google.com",
}
JUNK_WEBSITE_VALUES = {"", "n/a", "na", "none", "null", "tbd", "-", "http://", "https://"}

# Bundled public-suffix snapshot only: never fetch the list at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

OUTPUT_COLUMNS = [
    "county_code", "county_name", "district_code", "district_name", "district_type", "nces_id",
    "website_raw", "website_domain", "website_flag",
    "email_domain", "assessed_domain", "domain_source", "domain_flag", "domain_mismatch",
    "shared_domain", "shared_with_count",
]


def unwrap_excel(value: str) -> str:
    """The directory writes codes as ="01" so Excel keeps leading zeros."""
    m = re.fullmatch(r'\s*=\s*"(.*)"\s*', value or "")
    return m.group(1) if m else (value or "").strip()


def registrable_domain(host: str) -> str:
    ext = _extract(host)
    if not ext.suffix or not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower()


def website_domain(raw: str) -> tuple[str, str]:
    """Return (domain, flag). Flag is '' on success, else why the domain is blank."""
    value = (raw or "").strip().lower()
    if value in JUNK_WEBSITE_VALUES:
        return "", "missing"
    value = re.sub(r"^[a-z]+://", "", value)
    host = value.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not looks_like_domain(host):
        return "", "junk_value"
    domain = registrable_domain(host)
    if not domain:
        return "", "junk_value"
    if domain in THIRD_PARTY_HOSTS or host in THIRD_PARTY_HOSTS:
        return "", "third_party_host"
    return domain, ""


def email_domain(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" not in address:
        return ""
    dom = address.rsplit("@", 1)[1].strip().rstrip(".")
    if not looks_like_domain(dom):
        return ""
    return registrable_domain(dom) or ""


def district_type(row: dict) -> str:
    if unwrap_excel(row.get("County Code", "")) == "80":
        return "charter"
    if (row.get("County Name") or "").strip().upper() == "AGENCY":
        return "agency"
    name = (row.get("District Name") or "").lower()
    if "special services" in name:
        return "special_services"
    if "vocational" in name or "technical" in name or "career" in name:
        return "vocational"
    return "regular"


def derive(row: dict) -> dict:
    wd, wflag = website_domain(row.get("Website", ""))
    candidates = [
        ("supt_email", email_domain(row.get("Supt. EMail", ""))),
        ("ba_email", email_domain(row.get("BA Email", ""))),
    ]
    candidates = [(src, d) for src, d in candidates if d]
    # Prefer a district-owned email domain over a consumer one if the two contacts differ.
    non_consumer = [(s, d) for s, d in candidates if d not in CONSUMER_PROVIDERS]
    if non_consumer:
        source, edom = non_consumer[0]
    elif candidates:
        source, edom = candidates[0]
    else:
        source, edom = "", ""

    if edom:
        assessed, src = edom, source
    elif wd:
        assessed, src = wd, "website"
    else:
        assessed, src = "", "none"
    flag = ""
    if not assessed:
        flag = "no_domain"
    elif assessed in CONSUMER_PROVIDERS:
        flag = "consumer_provider"

    return {
        "county_code": unwrap_excel(row.get("County Code", "")),
        "county_name": (row.get("County Name") or "").strip().title(),
        "district_code": unwrap_excel(row.get("District Code", "")),
        "district_name": (row.get("District Name") or "").strip(),
        "district_type": district_type(row),
        "nces_id": unwrap_excel(row.get("NCES ID", "")),
        "website_raw": (row.get("Website") or "").strip(),
        "website_domain": wd,
        "website_flag": wflag,
        "email_domain": edom,
        "assessed_domain": assessed,
        "domain_source": src,
        "domain_flag": flag,
        "domain_mismatch": bool(edom and wd and edom != wd),
        "shared_domain": False,
        "shared_with_count": 0,
    }


def parse_directory(text: str) -> list[dict]:
    lines = text.splitlines()
    body = "\n".join(lines[PREAMBLE_LINES:])
    reader = csv.DictReader(io.StringIO(body))
    rows = [derive(r) for r in reader if any((v or "").strip() for v in r.values())]
    counts = Counter(r["assessed_domain"] for r in rows if r["assessed_domain"])
    for r in rows:
        n = counts.get(r["assessed_domain"], 0)
        r["shared_domain"] = n > 1
        r["shared_with_count"] = n - 1 if n else 0
    return rows


def fetch(raw_path: Path) -> str:
    resp = requests.get(SOURCE_URL, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    raw_path.write_bytes(resp.content)
    return resp.content.decode("latin-1")


def report(rows: list[dict]) -> None:
    def pct(n: int) -> str:
        return f"{100 * n / len(rows):.0f}%"

    print(f"districts: {len(rows)}")
    for t, n in sorted(Counter(r["district_type"] for r in rows).items(), key=lambda x: -x[1]):
        print(f"  {t:17s} {n}")
    print("assessed domain source:")
    for s, n in Counter(r["domain_source"] for r in rows).most_common():
        print(f"  {s:17s} {n}  ({pct(n)})")
    print("flags:")
    for f, n in Counter(r["domain_flag"] for r in rows if r["domain_flag"]).most_common():
        print(f"  {f:17s} {n}")
    for f, n in Counter(r["website_flag"] for r in rows if r["website_flag"]).most_common():
        print(f"  website {f:9s} {n}")
    mism = sum(r["domain_mismatch"] for r in rows)
    print(f"email domain != website domain: {mism} ({pct(mism)})")
    shared = {r["assessed_domain"] for r in rows if r["shared_domain"]}
    print(f"shared domains: {len(shared)} domains used by "
          f"{sum(r['shared_domain'] for r in rows)} districts")
    print("flagged rows (no assessable domain / consumer provider):")
    for r in rows:
        if r["domain_flag"]:
            print(f"  [{r['domain_flag']}] {r['district_name']} ({r['county_name']}) "
                  f"website={r['website_raw']!r}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", default="districts_raw.csv", help="where to keep the untouched download")
    ap.add_argument("--out", default="districts.csv")
    ap.add_argument("--offline", action="store_true", help="re-parse --raw instead of downloading")
    args = ap.parse_args(argv)

    raw_path = Path(args.raw)
    if args.offline:
        text = raw_path.read_bytes().decode("latin-1")
    else:
        print(f"fetching {SOURCE_URL}")
        text = fetch(raw_path)
        print(f"saved raw copy to {raw_path} ({raw_path.stat().st_size:,} bytes)")

    rows = parse_directory(text)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {args.out}\n")
    report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
