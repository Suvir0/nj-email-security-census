# Grading rubric

Each district gets one letter, A through F, from two things only: its **DMARC** policy and
whether its **SPF** record is valid. Everything else the census collects (DKIM, MTA-STS,
TLS-RPT, DNSSEC, mail provider) is recorded and summarised but does not move the grade.
The code that implements this table is `census/grade.py`; the tests in
`tests/test_grade.py` have one case per row. Change all three together.

## Definitions

**Valid SPF** means all of:

- exactly one TXT record starting `v=spf1` at the domain (two or more is a permanent error
  under RFC 7208 and receivers treat it as no SPF);
- it ends in `-all` (fail) or `~all` (softfail). Both tell receivers that unlisted senders
  are not legitimate; DMARC treats them the same way;
- it needs at most 10 DNS lookups to evaluate, counting `include:`, `redirect=`, `a`, `mx`,
  `ptr` and `exists` terms recursively (RFC 7208 §4.6.4), with at most 2 "void" lookups
  (includes pointing at names with no SPF), and no include loop.

**Broken SPF** is anything else: no record, `+all` (anyone may send), `?all` or no `all`
term (no opinion, so no protection), more than one record, or over the lookup limit.

**DMARC policy** is the `p=` tag of the single `v=DMARC1` TXT record at `_dmarc.<domain>`.
`pct=` defaults to 100. `sp=` (subdomain policy) defaults to `p`. `rua=` means the domain
has asked for aggregate reports, which is how an operator sees what is failing.

## The table

| Grade | DMARC | SPF | Meaning |
|---|---|---|---|
| **A** | `p=reject`, `pct=100`, `sp` absent or `reject` | valid | Spoofed mail claiming to be the district is rejected outright, for the domain and its subdomains. |
| **B** | `p=reject` with a weakness: `pct<100` or `sp` weaker than `reject` | valid | Enforcing, but with a gap (partial rollout, or subdomains unprotected). |
| **B** | `p=quarantine`, `pct=100` | valid | Spoofed mail goes to spam rather than being refused. Real protection, one step short. |
| **C** | `p=quarantine`, `pct<100` | valid | Quarantine applied to only a sample of mail. |
| **C** | `p=none` **with** `rua` | valid | Monitoring mode: nothing is blocked, but the district is collecting reports, which is the normal first step toward enforcement. |
| **D** | `p=none` **without** `rua` | valid | A DMARC record exists but neither blocks nor reports. Cosmetic. |
| **D** | any policy | broken | See "the SPF cap" below. |
| **F** | none, or invalid (no `p=`, unknown `p=` value, two records) | any | Nothing stops anyone from sending mail as the district. |
| **N/A** | | | Not graded: the assessed domain is a consumer mailbox provider (gmail.com etc.), no domain could be determined, or a DNS lookup failed. |

### The SPF cap

Broken SPF caps the grade at **D** no matter what DMARC says. Reason: DMARC passes when
*either* SPF or DKIM aligns. With `+all`, SPF passes for every sender on earth, so
`p=reject` blocks nothing. With SPF missing or over the lookup limit, DMARC is leaning
entirely on DKIM, which this census cannot verify (see below). A `p=reject` record on top
of `+all` is arguably worse than no record because it looks secure in a checklist.

### Worked examples

- `v=DMARC1; p=reject; rua=mailto:...` + `v=spf1 include:_spf.google.com ~all` → **A**
- `v=DMARC1; p=reject; pct=25` + valid SPF → **B** (pct)
- `v=DMARC1; p=reject; sp=none` + valid SPF → **B** (subdomains open)
- `v=DMARC1; p=quarantine; rua=...` + valid SPF → **B**
- `v=DMARC1; p=none; rua=mailto:...` + valid SPF → **C**
- `v=DMARC1; p=none` + valid SPF → **D**
- `v=DMARC1; p=reject` + `v=spf1 +all` → **D** (cap)
- `v=DMARC1; p=reject` + two SPF records → **D** (cap)
- no `_dmarc` record + perfect SPF → **F**
- `v=DMARC1; pct=100` (no `p=`) → **F** (invalid)

## Why DKIM is not scored

DKIM public keys live at `<selector>._domainkey.<domain>`, and the selector name is
chosen by whoever set it up. There is no way to enumerate selectors with DNS alone. The
census probes a handful of common ones (`google`, `selector1`, `selector2`, `default`,
`k1`, `s1`, `s2`), which covers the Google Workspace and Microsoft 365 defaults, and
records the result as:

- `found`: at least one probed selector holds a key that is not revoked. DKIM is in use.
- `not_found`: none of the probed selectors exist. DKIM **may still be configured** under
  another selector name. This is absence of evidence, not evidence of absence.
- `unknown`: a lookup failed; re-run.

Because "not found" cannot be distinguished from "uses a different selector", scoring it
would penalise districts for the census's own blind spot. It is reported in aggregate so
the reader can see how common the default selectors are, and nothing more.

## Why MTA-STS, TLS-RPT and DNSSEC are not scored

They protect different things (transport encryption and DNS integrity, not sender
identity), adoption is low everywhere including in the private sector, and the MTA-STS
*mode* lives in an HTTPS policy file the census deliberately does not fetch. They are
reported as adoption percentages only.

## Known limits of the grade

- It is a snapshot of DNS at the time of the lookup. Timestamps are stored per check.
- It grades the domain the district's listed superintendent or business administrator
  uses for email, which is the domain that matters, but it does not cover other domains a
  district may also send from.
- Several districts share one email domain (a county consortium, for example). They get
  the same grade because it is the same domain. `summary.py --unique-domains` counts each
  such domain once.
- SPF validity is syntactic: the census does not evaluate whether the listed IP ranges are
  the ones the district actually sends from.
