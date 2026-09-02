#!/usr/bin/env python3
"""Step 5: aggregate statistics from results.json. Prints tables only; never a district
name or domain. Per-district data stays in the local results files.

    uv run summary.py                  # all districts
    uv run summary.py --type regular   # one district type
    uv run summary.py --unique-domains # count each shared mail domain once
    uv run summary.py --markdown       # paste-ready tables
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

GRADES = ["A", "B", "C", "D", "F", "N/A"]
POLICIES = ["reject", "quarantine", "none", "missing", "invalid"]


def dmarc_bucket(rec: dict) -> str:
    d = rec["checks"]["dmarc"]
    if not d["present"]:
        return "missing"
    if not d["valid"]:
        return "invalid"
    return d["policy"]


def table(title: str, header: list[str], rows: list[list], markdown: bool) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)] if rows else [len(h) for h in header]
    lines = [f"\n{title}"]
    if markdown:
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join("---" for _ in header) + "|")
        lines += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    else:
        fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
        lines.append(fmt.format(*header))
        lines.append(fmt.format(*["-" * w for w in widths]))
        lines += [fmt.format(*[str(x) for x in r]) for r in rows]
    return "\n".join(lines)


def dist_row(label: str, items: list[dict], keys: list[str], keyfn) -> list:
    n = len(items)
    counts = Counter(keyfn(r) for r in items)
    cells = [label, n]
    for k in keys:
        c = counts.get(k, 0)
        cells.append(f"{c} ({100 * c / n:.0f}%)" if n else "0")
    return cells


def breakdown(title: str, items: list[dict], groupfn, keys: list[str], keyfn, markdown: bool,
              min_group: int = 1, sort_by_size: bool = False) -> str:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in items:
        groups[groupfn(r)].append(r)
    names = sorted(groups, key=(lambda g: -len(groups[g])) if sort_by_size else None)
    rows = [dist_row(g, groups[g], keys, keyfn) for g in names if len(groups[g]) >= min_group]
    return table(title, ["group", "n"] + keys, rows, markdown)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default="results.json")
    ap.add_argument("--type", help="district_type filter: regular, charter, vocational, special_services, agency")
    ap.add_argument("--unique-domains", action="store_true", help="count each assessed domain once")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args(argv)

    data = json.loads(Path(args.results).read_text())
    meta, all_recs = data["meta"], data["districts"]
    recs = [r for r in all_recs if not args.type or r["district_type"] == args.type]
    # Shared-domain figures describe the districts in scope, before any dedup.
    shared_districts = sum(1 for r in recs if r["shared_domain"])
    shared_domains = len({r["assessed_domain"] for r in recs if r["shared_domain"]})
    if args.unique_domains:
        seen, uniq = set(), []
        for r in recs:
            key = r["assessed_domain"] or r["district_code"]
            if key not in seen:
                seen.add(key)
                uniq.append(r)
        recs = uniq
    unit = "unique domains" if args.unique_domains else "districts"
    md = args.markdown

    graded = [r for r in recs if r["grade"] != "N/A"]
    na_reasons = Counter(r["domain_flag"] or "dns_error" for r in recs if r["grade"] == "N/A")
    errors = sum(1 for r in recs if any(c.get("error") for c in r["checks"].values()))

    out = [
        f"NJ K-12 Email Security Census — aggregate summary",
        f"generated {meta['generated_at']}  source run: {len(all_recs)} districts, "
        f"resolvers {', '.join(meta['resolvers'])}",
        f"scope: {len(recs)} {unit}" + (f" (type={args.type})" if args.type else ""),
        f"graded: {len(graded)}   not graded: {len(recs) - len(graded)} "
        + (f"({', '.join(f'{k}={v}' for k, v in na_reasons.items())})" if na_reasons else ""),
        f"shared mail domains: {shared_domains} domains covering {shared_districts} districts",
        f"rows with a DNS error in at least one check: {errors}",
    ]

    out.append(table("Grade distribution", ["grade", "n", "%"],
                     [[g, Counter(r["grade"] for r in recs)[g],
                       f"{100 * Counter(r['grade'] for r in recs)[g] / len(recs):.0f}%" if recs else "0"]
                      for g in GRADES], md))
    out.append(breakdown("DMARC policy by district type", recs, lambda r: r["district_type"],
                         POLICIES, dmarc_bucket, md))
    out.append(breakdown("DMARC policy by county", recs, lambda r: r["county_name"],
                         POLICIES, dmarc_bucket, md))
    out.append(breakdown("Grade by county", recs, lambda r: r["county_name"], GRADES,
                         lambda r: r["grade"], md))
    out.append(breakdown("DMARC policy by mail provider", graded,
                         lambda r: r["checks"]["mx"]["provider"] or "unknown", POLICIES, dmarc_bucket,
                         md, sort_by_size=True))
    out.append(breakdown("Grade by mail provider", graded,
                         lambda r: r["checks"]["mx"]["provider"] or "unknown", GRADES,
                         lambda r: r["grade"], md, sort_by_size=True))

    def spf_bucket(r):
        s = r["checks"]["spf"]
        if not s["present"]:
            return "missing"
        if s["lookup_limit_exceeded"]:
            return "over limit"
        if s["record_count"] > 1:
            return "multiple"
        return {"-": "-all", "~": "~all", "?": "?all", "+": "+all", None: "no all"}[s["all_qualifier"]]

    out.append(breakdown("SPF status by district type", graded, lambda r: r["district_type"],
                         ["-all", "~all", "?all", "+all", "no all", "multiple", "over limit", "missing"],
                         spf_bucket, md))

    def other_bucket(name):
        def f(r):
            c = r["checks"]
            return {
                "dkim": c["dkim"]["status"],
                "mta_sts": "yes" if c["mta_sts"]["present"] else "no",
                "tlsrpt": "yes" if c["mta_sts"]["tlsrpt"]["present"] else "no",
                "dnssec": ("signed, broken proof" if c["dnssec"].get("nonexistence_proof_broken")
                           else "signed" if c["dnssec"]["signed"] else "unsigned"),
                "rua": "yes" if c["dmarc"]["rua"] else "no",
            }[name]
        return f

    n = len(graded) or 1
    other_rows = []
    for label, name, keys in [
        ("DKIM (common selectors)", "dkim", ["found", "not_found", "unknown"]),
        ("DMARC rua reporting", "rua", ["yes", "no"]),
        ("MTA-STS record", "mta_sts", ["yes", "no"]),
        ("TLS-RPT record", "tlsrpt", ["yes", "no"]),
        ("DNSSEC", "dnssec", ["signed", "signed, broken proof", "unsigned"]),
    ]:
        c = Counter(other_bucket(name)(r) for r in graded)
        other_rows.append([label] + [f"{k}: {c[k]} ({100 * c[k] / n:.0f}%)" for k in keys])
    out.append(table(f"Other signals (graded {unit} only)", ["check", "", "", ""],
                     [r + [""] * (4 - len(r)) for r in other_rows], md))
    out.append("  'signed, broken proof' = DNSSEC-signed zone whose proof of non-existence fails "
               "validation; strict validators get SERVFAIL for missing names (e.g. DKIM selectors).")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
