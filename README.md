# NJ K-12 Email Security Census

A passive, DNS-only survey of the email authentication posture of every New Jersey public
school district: whether a district's domain tells the world's mail servers how to reject
mail that pretends to come from it.

Phase 1 (this repository) is the data collection pipeline. There is no dashboard. Raw
per-district results stay on the machine that ran the census; only aggregate statistics
are intended for publication. See **Ethics** below before doing anything with the output.

## How it works, in one paragraph

The pipeline downloads the New Jersey Department of Education's public directory of
school districts, takes each district's email domain from the contact information in that
directory, and then asks a public DNS resolver the same handful of questions that any
mail server asks when it receives a message: does this domain publish SPF, DMARC, DKIM,
MTA-STS, what are its MX records, and is its DNS zone signed. From the answers it assigns
a letter grade per the [rubric](RUBRIC.md) and prints statewide, per-county and
per-provider aggregates.

## What each check means

**SPF (Sender Policy Framework).** A TXT record on the domain that lists which servers
are allowed to send mail using that domain in the envelope sender. It ends with an `all`
term whose qualifier says what to do with everyone else: `-all` (reject), `~all` (treat
as suspicious), `?all` (no opinion), `+all` (everyone is allowed, which makes the record
pointless). SPF may only require 10 DNS lookups to evaluate; a record that needs more is
treated by receivers as an error, so the census counts the lookups by following every
`include:` and `redirect=`.

**DMARC (Domain-based Message Authentication, Reporting and Conformance).** A TXT record
at `_dmarc.<domain>` that tells receivers what to do with a message that fails SPF and
DKIM: `p=none` (deliver it anyway, just report), `p=quarantine` (spam folder),
`p=reject` (refuse it). It can also cover subdomains (`sp=`), apply to only a percentage
of mail (`pct=`), and ask for aggregate reports (`rua=`), which is how an administrator
finds out who is spoofing them. DMARC is the record that actually stops impersonation;
SPF and DKIM on their own are only advisory.

**DKIM (DomainKeys Identified Mail).** A cryptographic signature on each outgoing message,
verified against a public key published at `<selector>._domainkey.<domain>`. Because the
selector name is arbitrary, DNS alone cannot prove DKIM is absent. The census probes the
selectors that Google Workspace and Microsoft 365 use by default plus a few common
generic ones, and reports `found` / `not_found` / `unknown`. It is not part of the grade.

**MTA-STS (Mail Transfer Agent Strict Transport Security) and TLS-RPT.** MTA-STS tells
sending servers to insist on an encrypted, certificate-validated connection when
delivering to the domain. Its DNS half is a TXT record at `_mta-sts.<domain>`; the policy
itself (including the `mode`) sits on an HTTPS server, which the census does **not**
fetch, because that would contact district infrastructure. TLS-RPT (`_smtp._tls`) is the
matching reporting record. Both are recorded as present/absent only.

**MX and mail provider.** The MX records name the servers that receive the domain's mail.
The census classifies them into Google Workspace, Microsoft 365, a mail security gateway
(Proofpoint, Mimecast, Barracuda, and a few others), self-hosted, or other, purely from
the hostnames. This is used to break the statistics down by provider, since most
districts inherit their defaults from the provider.

**DNSSEC.** Whether the domain's DNS zone is cryptographically signed, determined from the
DS record at the parent, the DNSKEY record at the zone, and the "authenticated data" flag
returned by a validating public resolver. Unsigned DNS is the norm; this is recorded for
context and not graded. One real-world wrinkle is also recorded: some signed zones (seen
on certain registrar-operated nameservers) fail validation for names that *do not exist*,
so a validating resolver answers SERVFAIL instead of "no such record". When the census
hits that, it retries once with DNSSEC checking disabled, uses that answer, and flags the
domain `nonexistence_proof_broken`. It matters for email because a strictly validating
receiver looking up a DKIM selector on such a domain gets an error rather than an answer.

## Methodology

- **District list.** The "Public School Districts" CSV linked from the NJDOE School
  Directory (<https://homeroom6.doe.nj.gov/directory/>). All 683 rows are kept and tagged
  by type: regular, charter (county code 80), vocational/technical, special services, and
  one state agency. The raw download is kept as `districts_raw.csv` for provenance.
- **Which domain is assessed.** The domain part of the superintendent's listed email
  address, else the business administrator's, else the website's registrable domain. The
  directory's website and email domains differ for about one district in five (shared
  county consortia, legacy `k12.nj.us` mail behind a vanity website), and it is the email
  domain that SPF and DMARC protect. Only the domain is retained; addresses are discarded
  at parse time and never written to disk. Domains are never guessed: if the directory
  does not provide one, the district is flagged and left ungraded.
- **Consumer providers.** A few very small districts list a gmail.com or similar address.
  Their row is kept and flagged `consumer_provider` and their grade is `N/A`, because the
  posture of gmail.com is Google's, not the district's.
- **Shared domains.** When several districts use the same email domain, the domain is
  looked up once and each district receives the same result, flagged `shared_domain`.
  `summary.py --unique-domains` counts each domain once instead.
- **Resolver.** Queries go to Cloudflare's public resolver (1.1.1.1 / 1.0.0.1) with
  Google (8.8.8.8) as fallback, with the DNSSEC "DO" bit set so the resolver reports
  validation status. Query types are TXT, MX, DS and DNSKEY only. A SERVFAIL is retried
  once with the "checking disabled" flag so a DNSSEC validation failure is recorded as
  such rather than as a missing record or an error.
- **Rate limiting and caching.** A global token bucket (default 5 queries/second) shared by
  4 worker threads, 3-second timeouts with two retries. Every answer is cached in
  `cache/dns_cache.sqlite` for 7 days with its timestamp, so re-grading or re-summarising
  never re-queries; `--refresh` forces new lookups. A full statewide run is roughly 10,000
  queries and takes about half an hour cold; a second run takes seconds.
- **Timestamps.** Every check in `results.json` carries `queried_at` (UTC, ISO 8601) so a
  finding can be tied to the moment it was observed.
- **Grading.** See [RUBRIC.md](RUBRIC.md). Grades come from SPF and DMARC only.

### Limits to keep in mind

- DNS is a point-in-time observation. Districts change records; re-run before relying on
  a specific finding.
- The DKIM check can prove presence, never absence.
- SPF is judged on syntax and lookup count, not on whether the listed senders are correct.
- MTA-STS mode is unknown by design (the policy file is not fetched).
- A district may send mail from domains other than the one assessed.
- The directory is maintained by NJDOE from district submissions; a stale contact address
  means a stale domain. Mismatches between website and email domain are flagged in
  `districts.csv` for review.

## Running it

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

```bash
uv run pytest
```

```bash
uv run fetch_districts.py
```

```bash
uv run checks.py --limit 20
```

```bash
uv run checks.py
```

```bash
uv run summary.py
```

Useful variants: `uv run checks.py --domain example.org` prints the full check output for
one domain and writes nothing; `uv run summary.py --type regular --unique-domains
--markdown` produces paste-ready tables for regular districts counting each mail domain
once; `uv run fetch_districts.py --offline` re-parses the saved raw download.

### Files

| File | Purpose |
|---|---|
| `fetch_districts.py` | Download the NJDOE directory, derive `districts.csv` |
| `checks.py` | Run all checks for every district, write `results.json` / `results.csv` |
| `summary.py` | Aggregate statistics; never prints a district name |
| `census/dns_client.py` | Public-resolver client with rate limit and SQLite cache |
| `census/parsers.py` | Pure parsers for SPF, DMARC, DKIM, MTA-STS, TLS-RPT, MX |
| `census/checks.py` | Per-domain checks built on an injected `resolve()` callable |
| `census/grade.py` | The rubric as code |
| `tests/` | Offline tests with fake DNS records |
| `RUBRIC.md` | The grading rubric and its rationale |

`results.json` holds, per district: the identity fields from `districts.csv`, the full
output of each check (raw records, parsed fields, `queried_at`, any error), the grade and
the list of reasons behind it. `results.csv` is a flat one-row-per-district projection of
the key fields for spreadsheet use.

## Ethics

**Passive only.** The census never connects to a district's mail server, web server, or
any other system. It never sends email, never opens a TCP connection to a district host,
never scans ports. The only network activity is (1) one HTTPS download of NJDOE's own
public directory and (2) DNS queries to a public recursive resolver, which are identical
in kind to what every mail server on the internet performs when it receives a message
claiming to be from the district. The MTA-STS policy file is deliberately not fetched
because that would require an HTTPS request to district infrastructure.

**Polite.** Queries are rate-limited and cached so that even the public resolver sees a
light, bounded load, and the districts' authoritative name servers see at most the
resolver's normal cache-miss traffic.

**Minimal data.** The directory lists names and email addresses of district officials.
The pipeline extracts the email *domain* and discards the address; no personal data from
the directory is written to any output file. One caveat: `results.json` stores each
district's raw DMARC record verbatim, and a DMARC record contains whatever `rua=`
reporting address the district chose to publish in public DNS. A few districts use a
named administrator's mailbox for that. It is public information by construction, but it
is one more reason `results.json` stays local.

**Aggregate results are what gets published.** The purpose of the census is a statewide
picture (what share of districts enforce DMARC, how that varies by county and by mail
provider) to inform policy and support. `summary.py` prints only aggregates and will not
print a district name.

**District-level findings are shared privately first.** Before any public release of
anything that could identify a district's posture, district-level results are to be
shared with the districts themselves and with NJCCIC (the New Jersey Cybersecurity and
Communications Integration Cell), so that a weak grade is an invitation to fix a DNS
record, not a public shaming. `results.json`, `results.csv`, `districts_raw.csv` and the
DNS cache are git-ignored for that reason; keep them local.

**No exploitation.** Nothing here demonstrates, tests, or facilitates spoofing. Knowing
that a domain lacks DMARC is public information available to anyone with `dig`; the
census merely counts it.
