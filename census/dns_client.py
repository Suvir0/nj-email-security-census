"""Polite, cached DNS resolver.

Design constraints this module enforces:
- Queries go to a *public recursive resolver* (Cloudflare by default), never to a
  district's authoritative name servers, and never anything but stub queries via
  ``dns.resolver``. No zone transfers, no TCP to district hosts.
- A global token bucket limits the query rate across all worker threads.
- Every answer is cached in SQLite with a timestamp, so re-runs and re-grades are free
  and shared domains / shared includes are looked up once.

The public surface is ``CachedResolver.resolve(name, rtype) -> Answer``. Checks depend
only on that callable, so tests can substitute a dict-backed fake.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver

DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8"]
DEFAULT_TTL_SECONDS = 7 * 24 * 3600


@dataclass
class Answer:
    """Normalised DNS answer. ``status`` is one of NOERROR, NXDOMAIN, NOANSWER, ERROR."""

    name: str
    rtype: str
    status: str
    records: list[str] = field(default_factory=list)
    ad: bool = False  # Authenticated Data flag from a validating resolver
    queried_at: str = ""
    error: str | None = None
    from_cache: bool = False
    # True when the validating resolver returned SERVFAIL and the answer below came from
    # a retry with the Checking Disabled (CD) flag. Almost always means the zone is
    # DNSSEC-signed but its proof of non-existence does not validate.
    cd_fallback: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "NOERROR"

    def to_json(self) -> str:
        return json.dumps(
            {"status": self.status, "records": self.records, "ad": self.ad,
             "error": self.error, "cd_fallback": self.cd_fallback}
        )


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TokenBucket:
    """Simple thread-safe rate limiter: at most ``rate`` permits per second."""

    def __init__(self, rate: float, burst: int = 2):
        self.rate = rate
        self.capacity = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(wait)


class Cache:
    """SQLite cache keyed by (name, rtype). Safe for use from several threads."""

    def __init__(self, path: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.path = Path(path)
        self.ttl = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS dns (name TEXT, rtype TEXT, queried_at TEXT, "
            "queried_ts REAL, answer TEXT, PRIMARY KEY (name, rtype))"
        )
        self.conn.commit()

    def get(self, name: str, rtype: str) -> Answer | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT queried_at, queried_ts, answer FROM dns WHERE name=? AND rtype=?",
                (name, rtype),
            ).fetchone()
        if not row:
            return None
        queried_at, ts, answer = row
        if time.time() - ts > self.ttl:
            return None
        data = json.loads(answer)
        if data["status"] == "ERROR":
            return None  # never serve a cached failure; retry it
        return Answer(
            name=name, rtype=rtype, status=data["status"], records=data["records"],
            ad=data.get("ad", False), queried_at=queried_at, error=data.get("error"),
            from_cache=True, cd_fallback=data.get("cd_fallback", False),
        )

    def put(self, ans: Answer) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO dns VALUES (?,?,?,?,?)",
                (ans.name, ans.rtype, ans.queried_at, time.time(), ans.to_json()),
            )
            self.conn.commit()

    def stats(self) -> dict:
        with self.lock:
            n = self.conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0]
        return {"entries": n, "path": str(self.path)}


class CachedResolver:
    def __init__(
        self,
        nameservers: list[str] | None = None,
        cache_path: Path | str = "cache/dns_cache.sqlite",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        qps: float = 5.0,
        timeout: float = 3.0,
        retries: int = 2,
        refresh: bool = False,
    ):
        self.nameservers = nameservers or DEFAULT_NAMESERVERS
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        # DO bit: ask the validating resolver to tell us (via AD) whether the answer
        # was DNSSEC-validated. Does not change *where* we query.
        self.resolver.use_edns(0, dns.flags.DO, 1232)
        # Second resolver with Checking Disabled, used only after a SERVFAIL so we can
        # tell "the zone's DNSSEC is broken for this name" from "the name is unreachable".
        self.resolver_cd = dns.resolver.Resolver(configure=False)
        self.resolver_cd.nameservers = self.nameservers
        self.resolver_cd.timeout = timeout
        self.resolver_cd.lifetime = timeout * 2
        self.resolver_cd.use_edns(0, dns.flags.DO, 1232)
        self.resolver_cd.flags = dns.flags.RD | dns.flags.CD
        self.retries = retries
        self.cache = Cache(Path(cache_path), ttl_seconds)
        self.bucket = TokenBucket(qps)
        self.refresh = refresh
        self.query_count = 0
        self.cache_hits = 0
        self._stats_lock = threading.Lock()

    def resolve(self, name: str, rtype: str = "TXT") -> Answer:
        name = name.lower().rstrip(".")
        rtype = rtype.upper()
        if not self.refresh:
            cached = self.cache.get(name, rtype)
            if cached:
                with self._stats_lock:
                    self.cache_hits += 1
                return cached
        ans = self._query(name, rtype)
        self.cache.put(ans)
        return ans

    def _query(self, name: str, rtype: str) -> Answer:
        last_error = "unknown"
        for attempt in range(self.retries + 1):
            self.bucket.acquire()
            with self._stats_lock:
                self.query_count += 1
            try:
                return self._one(self.resolver, name, rtype)
            except dns.resolver.NXDOMAIN:
                return Answer(name, rtype, "NXDOMAIN", [], False, utcnow_iso())
            except dns.resolver.NoNameservers as e:
                # SERVFAIL from every resolver: usually a DNSSEC validation failure.
                # Retry once with CD; if that works, the data is fine but the signatures
                # (typically the NSEC/NSEC3 proof of non-existence) are not.
                last_error = f"SERVFAIL: {e}"
                try:
                    self.bucket.acquire()
                    with self._stats_lock:
                        self.query_count += 1
                    ans = self._one(self.resolver_cd, name, rtype)
                    ans.cd_fallback = True
                    ans.ad = False
                    return ans
                except dns.resolver.NXDOMAIN:
                    return Answer(name, rtype, "NXDOMAIN", [], False, utcnow_iso(), cd_fallback=True)
                except dns.exception.DNSException as e2:
                    last_error = f"SERVFAIL even with CD: {e2}"
                break
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
                last_error = f"timeout: {e}"
                time.sleep(0.5 * (attempt + 1))
            except dns.exception.DNSException as e:
                last_error = f"{type(e).__name__}: {e}"
                break
        return Answer(name, rtype, "ERROR", [], False, utcnow_iso(), error=last_error)


    @staticmethod
    def _one(resolver: dns.resolver.Resolver, name: str, rtype: str) -> Answer:
        resp = resolver.resolve(name, rtype, raise_on_no_answer=False)
        records = [_rdata_to_text(r) for r in resp.rrset] if resp.rrset else []
        ad = bool(resp.response.flags & dns.flags.AD)
        status = "NOERROR" if records else "NOANSWER"
        return Answer(name, rtype, status, records, ad, utcnow_iso())


def _rdata_to_text(rdata) -> str:
    """Render one rdata as a plain string: TXT strings are joined (multi-string records
    are concatenated per RFC 7208 §3.3), MX becomes the exchange host, others to_text()."""
    rt = rdata.rdtype
    if rt == dns.rdatatype.TXT:
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rt == dns.rdatatype.MX:
        return rdata.exchange.to_text()
    return rdata.to_text()
