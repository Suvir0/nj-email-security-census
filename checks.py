#!/usr/bin/env python3
"""Step 2–4: run the passive DNS checks for every district and write results.

    uv run checks.py                      # all districts in districts.csv
    uv run checks.py --limit 20           # first 20 (smoke test)
    uv run checks.py --domain example.org # one ad-hoc domain, prints JSON
    uv run checks.py --refresh            # ignore the DNS cache

Only DNS queries to a public resolver are made (see census/dns_client.py). Each unique
domain is checked once; districts that share a domain share the result.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from census.checks import check_domain
from census.dns_client import DEFAULT_NAMESERVERS, CachedResolver
from census.grade import grade

IDENTITY_COLUMNS = [
    "county_code", "county_name", "district_code", "district_name", "district_type", "nces_id",
    "website_domain", "email_domain", "assessed_domain", "domain_source", "domain_flag",
    "domain_mismatch", "shared_domain", "shared_with_count",
]

CSV_COLUMNS = IDENTITY_COLUMNS + [
    "grade", "grade_reasons",
    "spf_present", "spf_record_count", "spf_all", "spf_lookup_count", "spf_lookup_limit_exceeded",
    "spf_queried_at",
    "dmarc_present", "dmarc_valid", "dmarc_policy", "dmarc_subdomain_policy", "dmarc_pct",
    "dmarc_rua", "dmarc_queried_at",
    "dkim_status", "dkim_selectors_found", "dkim_queried_at",
    "mta_sts_present", "tlsrpt_present", "mta_sts_queried_at",
    "mx_provider", "mx_hosts", "mx_queried_at",
    "dnssec_signed", "dnssec_validated", "dnssec_nonexistence_proof_broken", "dnssec_queried_at",
    "dns_errors",
]


def load_districts(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["domain_mismatch"] = r["domain_mismatch"] == "True"
        r["shared_domain"] = r["shared_domain"] == "True"
        r["shared_with_count"] = int(r["shared_with_count"] or 0)
    return rows


def flatten(rec: dict) -> dict:
    c = rec["checks"]
    errors = [k for k in ("spf", "dmarc", "dkim", "mta_sts", "mx", "dnssec") if c[k].get("error")]
    row = {k: rec[k] for k in IDENTITY_COLUMNS}
    row.update({
        "grade": rec["grade"],
        "grade_reasons": " | ".join(rec["grade_reasons"]),
        "spf_present": c["spf"]["present"],
        "spf_record_count": c["spf"]["record_count"],
        "spf_all": c["spf"]["all_qualifier"],
        "spf_lookup_count": c["spf"]["lookup_count"],
        "spf_lookup_limit_exceeded": c["spf"]["lookup_limit_exceeded"],
        "spf_queried_at": c["spf"]["queried_at"],
        "dmarc_present": c["dmarc"]["present"],
        "dmarc_valid": c["dmarc"]["valid"],
        "dmarc_policy": c["dmarc"]["policy"],
        "dmarc_subdomain_policy": c["dmarc"]["subdomain_policy"],
        "dmarc_pct": c["dmarc"]["pct"],
        "dmarc_rua": c["dmarc"]["rua"],
        "dmarc_queried_at": c["dmarc"]["queried_at"],
        "dkim_status": c["dkim"]["status"],
        "dkim_selectors_found": ",".join(c["dkim"]["selectors_found"]),
        "dkim_queried_at": c["dkim"]["queried_at"],
        "mta_sts_present": c["mta_sts"]["present"],
        "tlsrpt_present": c["mta_sts"]["tlsrpt"]["present"],
        "mta_sts_queried_at": c["mta_sts"]["queried_at"],
        "mx_provider": c["mx"]["provider"],
        "mx_hosts": ",".join(c["mx"]["mx_hosts"]),
        "mx_queried_at": c["mx"]["queried_at"],
        "dnssec_signed": c["dnssec"]["signed"],
        "dnssec_validated": c["dnssec"]["validated"],
        "dnssec_nonexistence_proof_broken": c["dnssec"].get("nonexistence_proof_broken", False),
        "dnssec_queried_at": c["dnssec"]["queried_at"],
        "dns_errors": ",".join(errors),
    })
    return row


def empty_checks() -> dict:
    """Placeholder for districts with no assessable domain, so every row has one shape."""
    base = {"queried_at": "", "error": None}
    return {
        "spf": {**base, "present": False, "record_count": 0, "records": [], "all_qualifier": None,
                "lookup_count": 0, "lookup_limit_exceeded": False},
        "dmarc": {**base, "present": False, "valid": False, "policy": None,
                  "subdomain_policy": None, "pct": None, "rua": False},
        "dkim": {**base, "status": "unknown", "selectors_found": []},
        "mta_sts": {**base, "present": False, "tlsrpt": {"present": False}},
        "mx": {**base, "provider": None, "mx_hosts": []},
        "dnssec": {**base, "signed": False, "validated": False, "nonexistence_proof_broken": False},
    }


def run(districts: list[dict], resolver: CachedResolver, workers: int, log=print) -> list[dict]:
    domains = sorted({d["assessed_domain"] for d in districts if d["assessed_domain"]})
    log(f"{len(districts)} districts, {len(domains)} unique domains, "
        f"{workers} workers, {resolver.bucket.rate:g} qps, resolvers {resolver.nameservers}")
    results: dict[str, dict] = {}
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_domain, dom, resolver.resolve): dom for dom in domains}
        for i, fut in enumerate(as_completed(futures), 1):
            dom = futures[fut]
            try:
                results[dom] = fut.result()
            except Exception as e:  # keep going; record the failure on the row
                log(f"  ! {dom}: {type(e).__name__}: {e}")
                results[dom] = empty_checks()
                for v in results[dom].values():
                    v["error"] = f"{type(e).__name__}: {e}"
            if i % 25 == 0 or i == len(domains):
                elapsed = time.monotonic() - started
                log(f"  {i}/{len(domains)} domains  {elapsed:.0f}s  "
                    f"queries={resolver.query_count} cache_hits={resolver.cache_hits}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = []
    for d in districts:
        checks = results.get(d["assessed_domain"]) or empty_checks()
        g, reasons = grade(checks["spf"], checks["dmarc"], d["domain_flag"])
        out.append({**d, "checks": checks, "grade": g, "grade_reasons": reasons, "run_id": run_id})
    return out


def write_outputs(records: list[dict], json_path: Path, csv_path: Path, resolver: CachedResolver) -> None:
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "resolvers": resolver.nameservers,
        "method": "passive DNS only; no connections to district mail or web servers",
        "district_count": len(records),
        "dns_queries_this_run": resolver.query_count,
        "cache_hits_this_run": resolver.cache_hits,
    }
    json_path.write_text(json.dumps({"meta": meta, "districts": records}, indent=1))
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in records:
            w.writerow(flatten(r))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--districts", default="districts.csv")
    ap.add_argument("--json", default="results.json")
    ap.add_argument("--csv", default="results.csv")
    ap.add_argument("--limit", type=int, help="only the first N districts")
    ap.add_argument("--domain", action="append", help="ad-hoc domain(s) to check; prints JSON, writes nothing")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--qps", type=float, default=5.0, help="global DNS queries per second")
    ap.add_argument("--nameserver", action="append", help=f"public resolver IP (default {DEFAULT_NAMESERVERS})")
    ap.add_argument("--cache", default="cache/dns_cache.sqlite")
    ap.add_argument("--cache-ttl-days", type=float, default=7)
    ap.add_argument("--refresh", action="store_true", help="bypass the DNS cache")
    args = ap.parse_args(argv)

    resolver = CachedResolver(
        nameservers=args.nameserver, cache_path=args.cache,
        ttl_seconds=int(args.cache_ttl_days * 86400), qps=args.qps, refresh=args.refresh,
    )
    log = lambda *a: print(*a, file=sys.stderr)  # noqa: E731

    if args.domain:
        for dom in args.domain:
            checks = check_domain(dom.lower().strip("."), resolver.resolve)
            g, reasons = grade(checks["spf"], checks["dmarc"])
            print(json.dumps({"domain": dom, "grade": g, "grade_reasons": reasons, "checks": checks}, indent=1))
        log(f"queries={resolver.query_count} cache_hits={resolver.cache_hits}")
        return 0

    districts = load_districts(Path(args.districts))
    if args.limit:
        districts = districts[: args.limit]
    records = run(districts, resolver, args.workers, log)
    write_outputs(records, Path(args.json), Path(args.csv), resolver)
    log(f"wrote {args.json} and {args.csv}; queries={resolver.query_count} "
        f"cache_hits={resolver.cache_hits} cache={resolver.cache.stats()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
