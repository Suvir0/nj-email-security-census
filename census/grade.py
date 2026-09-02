"""Letter grade from SPF + DMARC findings. The rubric is documented in RUBRIC.md; keep the
two in sync. DKIM, MTA-STS and DNSSEC are recorded but deliberately not scored."""

from __future__ import annotations

GRADE_ORDER = ["A", "B", "C", "D", "F"]


def spf_is_valid(spf: dict) -> tuple[bool, list[str]]:
    """'Valid SPF' per RUBRIC.md: one record, -all or ~all, within the 10-lookup limit."""
    problems: list[str] = []
    if not spf.get("present"):
        return False, ["SPF: no record"]
    if spf.get("record_count", 0) > 1:
        problems.append("SPF: multiple records (permerror)")
    q = spf.get("all_qualifier")
    if q == "+":
        problems.append("SPF: +all lets anyone send")
    elif q == "?":
        problems.append("SPF: ?all is neutral (no protection)")
    elif q is None:
        problems.append("SPF: no 'all' mechanism")
    if spf.get("lookup_limit_exceeded"):
        problems.append(f"SPF: {spf.get('lookup_count')} DNS lookups exceeds limit of 10 (permerror)")
    if spf.get("include_loop"):
        problems.append("SPF: include loop")
    return (not problems), problems


def grade(spf: dict, dmarc: dict, domain_flag: str = "") -> tuple[str, list[str]]:
    """Return (grade, reasons). Grade is 'A'..'F' or 'N/A'."""
    reasons: list[str] = []
    if domain_flag == "consumer_provider":
        return "N/A", ["assessed domain is a consumer mailbox provider; posture is not the district's"]
    if domain_flag == "no_domain":
        return "N/A", ["no assessable domain"]
    if spf.get("error") or dmarc.get("error"):
        return "N/A", ["DNS lookup error; re-run before grading"]

    # ---- F: no usable DMARC
    if not dmarc.get("present"):
        return "F", ["DMARC: no record at _dmarc"]
    if not dmarc.get("valid"):
        return "F", ["DMARC: record present but invalid: " + "; ".join(dmarc.get("parse_errors", []))]

    policy = dmarc["policy"]
    pct = dmarc.get("pct", 100)
    sp = dmarc.get("subdomain_policy") or policy
    rua = dmarc.get("rua", False)
    valid_spf, spf_problems = spf_is_valid(spf)
    reasons.append(f"DMARC: p={policy}, sp={sp}, pct={pct}, rua={'yes' if rua else 'no'}")
    reasons.append("SPF: valid" if valid_spf else "SPF: broken")
    reasons.extend(spf_problems)

    # ---- D cap: broken SPF caps at D regardless of DMARC policy
    if not valid_spf:
        reasons.append("grade capped at D because SPF is broken")
        return "D", reasons

    rank = {"none": 0, "quarantine": 1, "reject": 2}
    if policy == "reject":
        weak = []
        if pct < 100:
            weak.append(f"pct={pct} applies reject to only part of mail")
        if rank[sp] < rank["reject"]:
            weak.append(f"subdomain policy sp={sp} weaker than reject")
        if not weak:
            return "A", reasons
        reasons.extend(weak)
        return "B", reasons
    if policy == "quarantine":
        if pct < 100:
            reasons.append(f"pct={pct} applies quarantine to only part of mail")
            return "C", reasons
        return "B", reasons
    # policy == none
    if rua:
        reasons.append("p=none with rua reporting: monitoring mode")
        return "C", reasons
    reasons.append("p=none without rua: DMARC is not enforcing or reporting")
    return "D", reasons
