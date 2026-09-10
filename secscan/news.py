"""Recent-news enrichment for vulnerability classes.

Two sources, in order of usefulness:

1.  **CISA Known Exploited Vulnerabilities (KEV)** - the authoritative public
    list of CVEs with confirmed in-the-wild exploitation.  A KEV entry matching
    a finding's CWE is the strongest possible "this class is being exploited
    right now" signal, and it is free and unauthenticated.

2.  **NVD CVE API 2.0** - recent CVEs filtered by CWE id, which gives a
    volume signal (how often this weakness is still being published).

Both are fetched over HTTPS with urllib (no third-party dependencies), cached
on disk, and degrade silently to the curated offline dataset in knowledge.py
when the network is unavailable.  Nothing about the scanned code is ever sent:
the requests carry only CWE identifiers.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .knowledge import CURATED_AS_OF, NewsItem, VulnClass

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# cisa.gov sits behind an edge filter that rejects User-Agent strings containing
# a parenthetical comment (the conventional "(+url)" form returns HTTP 403), so
# keep this a bare product token. FALLBACK_UA is tried once on a 403.
USER_AGENT = "secscan/1.0"
FALLBACK_UA = "curl/8.7.1"
CACHE_TTL_SECONDS = 24 * 3600


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    d = Path(base) / "secscan"
    d.mkdir(parents=True, exist_ok=True)
    return d


# Certificate handling: verification stays ON. Some Python installs (notably
# python.org builds on macOS that never ran "Install Certificates.command")
# ship without a usable root store, so we look for a real CA bundle in the
# usual places rather than doing the tempting-but-wrong thing and turning
# verification off - which is a finding this very scanner reports (CWE-295).
CA_BUNDLE_CANDIDATES = (
    "/etc/ssl/cert.pem",                       # macOS / LibreSSL
    "/etc/ssl/certs/ca-certificates.crt",      # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",        # RHEL, Fedora
    "/usr/local/etc/openssl/cert.pem",         # Homebrew OpenSSL
)

LAST_ERROR: Optional[str] = None
_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _ssl_context() -> ssl.SSLContext:
    """A verifying SSL context, with a CA bundle located if the default is empty."""
    global _SSL_CONTEXT
    if _SSL_CONTEXT is not None:
        return _SSL_CONTEXT
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        try:
            import certifi  # type: ignore
            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            for candidate in CA_BUNDLE_CANDIDATES:
                if os.path.isfile(candidate):
                    try:
                        ctx = ssl.create_default_context(cafile=candidate)
                        break
                    except (ssl.SSLError, OSError):
                        continue
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    _SSL_CONTEXT = ctx
    return ctx


def _fetch_json(url: str, timeout: float = 12.0,
                user_agent: str = USER_AGENT) -> Optional[dict]:
    global LAST_ERROR
    req = urllib.request.Request(url, headers={"User-Agent": user_agent,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except ssl.SSLCertVerificationError as exc:
        LAST_ERROR = (f"TLS verification failed for {urllib.parse.urlsplit(url).netloc}: {exc}. "
                      "Install root certificates (macOS python.org builds: run "
                      "'Install Certificates.command' in /Applications/Python 3.x/, or pip install certifi).")
        return None
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 406) and user_agent != FALLBACK_UA:
            return _fetch_json(url, timeout, user_agent=FALLBACK_UA)
        LAST_ERROR = f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}"
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        LAST_ERROR = f"network error contacting {urllib.parse.urlsplit(url).netloc}: {exc}"
        return None
    except json.JSONDecodeError as exc:
        LAST_ERROR = f"malformed JSON from {urllib.parse.urlsplit(url).netloc}: {exc}"
        return None


def _cached_json(name: str, url: str, ttl: int = CACHE_TTL_SECONDS,
                 offline: bool = False, refresh: bool = False) -> Optional[dict]:
    path = cache_dir() / name
    if path.is_file() and not refresh:
        age = time.time() - path.stat().st_mtime
        if age < ttl or offline:
            try:
                return json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                pass
    if offline:
        return None
    data = _fetch_json(url)
    if data is not None:
        try:
            path.write_text(json.dumps(data))
        except OSError:
            pass
        return data
    # Network failed - fall back to a stale cache if we have one.
    if path.is_file():
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
    return None


@dataclass
class LiveSignal:
    """What the live feeds say about one vulnerability class."""

    kev_total: int = 0
    kev_recent: int = 0            # added within `window_days`
    kev_examples: Tuple[NewsItem, ...] = ()
    nvd_recent_count: Optional[int] = None
    window_days: int = 365
    source_note: str = ""

    @property
    def has_data(self) -> bool:
        return self.kev_total > 0 or bool(self.nvd_recent_count)


def _clip(text: str, limit: int) -> str:
    """Truncate on a word boundary so summaries do not end mid-word."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(",;:. ") + "…"


def _kev_matches(entry: dict, vc: VulnClass) -> bool:
    cwes = entry.get("cwes") or []
    if vc.cwe in cwes:
        return True
    haystack = " ".join([
        str(entry.get("vulnerabilityName", "")),
        str(entry.get("shortDescription", "")),
    ]).lower()
    return any(k in haystack for k in vc.feed_keywords)


def kev_signal(vc: VulnClass, kev: dict, window_days: int = 365) -> LiveSignal:
    vulns: Sequence[dict] = kev.get("vulnerabilities", []) or []
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    matches: List[Tuple[datetime, dict]] = []
    for entry in vulns:
        if not _kev_matches(entry, vc):
            continue
        try:
            added = datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        matches.append((added, entry))
    matches.sort(key=lambda t: t[0], reverse=True)
    recent = [m for m in matches if m[0] >= cutoff]

    examples = tuple(
        NewsItem(
            date=added.strftime("%Y-%m"),
            headline=f"{entry.get('cveID')}: {entry.get('vulnerabilityName', '').strip()}",
            summary=(_clip(str(entry.get("shortDescription", "")).strip(), 280) +
                     f" Known ransomware use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}."),
            source="CISA Known Exploited Vulnerabilities catalog",
            url=f"https://nvd.nist.gov/vuln/detail/{entry.get('cveID')}",
        )
        for added, entry in matches[:3]
    )
    return LiveSignal(
        kev_total=len(matches),
        kev_recent=len(recent),
        kev_examples=examples,
        window_days=window_days,
        source_note=f"CISA KEV catalog v{kev.get('catalogVersion', '?')} "
                    f"({kev.get('dateReleased', 'unknown date')})",
    )


def nvd_recent_count(vc: VulnClass, days: int = 120, offline: bool = False) -> Optional[int]:
    """How many CVEs with this CWE were published in the last `days` days."""
    if offline:
        return None
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 120))  # NVD caps ranges at 120 days
    params = {
        "cweId": vc.cwe,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "1",
    }
    cache_name = f"nvd-{vc.cwe.replace('-', '')}-{end.strftime('%Y%m%d')}.json"
    data = _cached_json(cache_name, f"{NVD_URL}?{urllib.parse.urlencode(params)}")
    if not data:
        return None
    total = data.get("totalResults")
    return int(total) if isinstance(total, int) else None


class NewsProvider:
    """Serves curated news, optionally enriched with live feed data."""

    def __init__(self, offline: bool = False, refresh: bool = False,
                 window_days: int = 365, use_nvd: bool = False):
        self.offline = offline
        self.window_days = window_days
        self.use_nvd = use_nvd and not offline
        self._kev: Optional[dict] = None
        self._signals: Dict[str, LiveSignal] = {}
        self.status = "curated dataset only (offline)"
        if not offline:
            self._kev = _cached_json("kev.json", KEV_URL, offline=offline, refresh=refresh)
            if self._kev:
                self.status = (f"curated dataset + {self._kev.get('count', '?')} live CISA KEV "
                               f"records ({self._kev.get('dateReleased', '?')[:10]})")
            else:
                detail = f": {LAST_ERROR}" if LAST_ERROR else ""
                self.status = f"curated dataset only (live feed unavailable{detail})"

    def signal(self, vc: VulnClass) -> Optional[LiveSignal]:
        if vc.key in self._signals:
            return self._signals[vc.key]
        if not self._kev:
            return None
        sig = kev_signal(vc, self._kev, self.window_days)
        if self.use_nvd:
            sig.nvd_recent_count = nvd_recent_count(vc, offline=self.offline)
        self._signals[vc.key] = sig
        return sig

    def items_for(self, vc: VulnClass, limit: int = 3) -> List[NewsItem]:
        """Live KEV entries first (they are the most current), then curated."""
        out: List[NewsItem] = []
        sig = self.signal(vc)
        if sig:
            out.extend(sig.kev_examples)
        seen = {i.headline for i in out}
        for item in vc.news:
            if item.headline not in seen:
                out.append(item)
        return out[:limit]

    def headline_stat(self, vc: VulnClass) -> Optional[str]:
        """One-line 'is this being exploited right now' summary."""
        sig = self.signal(vc)
        if not sig or not sig.has_data:
            return None
        bits: List[str] = []
        if sig.kev_total:
            bits.append(f"{sig.kev_total} CVE(s) of this type in CISA's known-exploited catalog"
                        + (f", {sig.kev_recent} added in the last {sig.window_days} days"
                           if sig.kev_recent else ""))
        if sig.nvd_recent_count:
            bits.append(f"{sig.nvd_recent_count} new {vc.cwe} CVEs published in NVD in the last 120 days")
        return "; ".join(bits) if bits else None

    def provenance(self) -> str:
        return (f"News: curated snapshot as of {CURATED_AS_OF}; live enrichment: {self.status}. "
                "Only CWE identifiers are sent to remote feeds - never your code.")
