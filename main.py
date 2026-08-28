#!/usr/bin/env python3
"""Node Harvester - incremental VPN node harvester for GitHub Actions.

Pipeline:
    1. RSSHub /telegram/channel/<name>  -> parse XML, regex node URIs (no t.me/s/ HTML).
       RSSHUB_BASE accepts a comma-separated mirror chain, tried in order.
    2. GitHub /search/code with multiple queries (vmess/vless/trojan/subscription)
       -> raw content -> recursive base64 decode. Query set configurable via
       GITHUB_QUERIES. Files deduped across queries; queries spaced 7s apart
       (/search/code allows 10 req/min).
    3. Diff against history.txt -> only never-seen nodes are NEW (incremental).
    4. Concurrent TCP liveness check of fresh nodes PLUS re-verification of the
       previous run's alive pool -> rolling subscription output.

State lives in git: history.txt / nodes.txt / nodes_base64.txt are committed
back to the repo by the workflow, because Actions runners are stateless.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOG = logging.getLogger("harvester")

# Comma-separated fallback chain: the public rsshub.app instance 403s
# datacenter IPs (GitHub Actions runners), so mirrors or a self-hosted
# instance can be listed and are tried in order, e.g.
#   RSSHUB_BASE="https://rss.example.com,https://rsshub.app"
# `or` (not getenv default): Actions passes unset vars.* as EMPTY STRINGS.
RSSHUB_BASES = [b.strip().rstrip("/")
                 for b in (os.getenv("RSSHUB_BASE") or "https://rsshub.app").split(",")
                 if b.strip()]
GITHUB_API = "https://api.github.com"
BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "history.txt"
NODES_FILE = BASE_DIR / "nodes.txt"
SUB_FILE = BASE_DIR / "nodes_base64.txt"

MAX_B64_DEPTH = 5          # recursion guard for nested base64 subscriptions
BLOB_MIN_LEN = 24          # do not even try to decode anything shorter
MAX_RAW_FILE_BYTES = 2_000_000

# Longest-first alternation so "ssr://" is not half-eaten by "ss".
# Unicode remark fragments (#备注) are intentionally truncated - URIs stay usable.
NODE_RE = re.compile(
    r"\b(?:vmess|vless|trojan|ssr|ss|hysteria2?|hy2|tuic)://[A-Za-z0-9+/=:.@%?&#-]+",
    re.IGNORECASE,
)
B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
TAG_RE = re.compile(r"<[^>]+>")


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------

def make_session(token: str | None = None) -> requests.Session:
    """Session with transport-level retries (429/5xx) and exponential backoff.

    Uses urllib3 v2 API only: allowed_methods, respect_retry_after_header.
    """
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=64)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "node-harvester/1.0 (+github-actions)",
        "Accept-Encoding": "gzip, deflate",
    })
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    return session


def github_get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """GET with manual handling of GitHub secondary rate limits (403 + Retry-After)."""
    resp = None
    for attempt in range(3):
        resp = session.get(url, timeout=(10, 30), **kwargs)
        if resp.status_code not in (403, 429):
            return resp
        wait = resp.headers.get("Retry-After", "")
        delay = min(float(wait), 120.0) if wait.isdigit() else 30.0 * (attempt + 1)
        LOG.warning("GitHub rate limit on %s (HTTP %d) - sleeping %.0fs",
                    url, resp.status_code, delay)
        time.sleep(delay)
    return resp  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Step 1 - RSSHub Telegram channels
# --------------------------------------------------------------------------

def harvest_text_nodes(text: str) -> set[str]:
    """Strip HTML tags, undo entity escaping (&amp; -> &), then regex node URIs."""
    plain = unescape(TAG_RE.sub(" ", text))
    return set(NODE_RE.findall(plain))


def fetch_rsshub(session: requests.Session, channels: list[str]) -> set[str]:
    """For each channel, try every RSSHub base in order; first success wins."""
    nodes: set[str] = set()
    for channel in channels:
        found: set[str] = set()
        for base in RSSHUB_BASES:
            url = f"{base}/telegram/channel/{channel}"
            try:
                resp = session.get(url, timeout=(10, 30))
                resp.raise_for_status()
                root = ET.fromstring(resp.content)
            except (requests.RequestException, ET.ParseError) as exc:
                LOG.warning("RSSHub %s: channel %r failed: %s", base, channel, exc)
                continue  # next mirror
            for element in root.iter():
                if element.text:  # sweeps title/description/content:encoded alike
                    found |= harvest_text_nodes(element.text)
            LOG.info("RSSHub %s: channel %r -> %d nodes", base, channel, len(found))
            break  # this channel succeeded - stop burning mirrors
        nodes |= found
    return nodes


# --------------------------------------------------------------------------
# Step 2 - GitHub code search radar
# --------------------------------------------------------------------------

def _try_b64_decode(text: str) -> str | None:
    """Decode standard or URL-safe base64; return UTF-8 text only if the result
    is >= 95% printable, otherwise None (rejects binary garbage)."""
    stripped = re.sub(r"\s+", "", text)
    padded = stripped + "=" * (-len(stripped) % 4)
    if len(padded) < 4:
        return None
    candidates = (padded, padded.translate(str.maketrans("-_", "+/")))
    for candidate in candidates:
        try:
            raw = base64.b64decode(candidate, validate=False)
        except (binascii.Error, ValueError):
            continue
        if not raw:
            return None
        sample = raw[:512]
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        if printable / max(len(sample), 1) < 0.95:
            continue
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None


def recursive_b64_nodes(text: str, depth: int = 0) -> set[str]:
    """Extract node URIs, recursing through nested base64 subscription blobs.

    Guards: depth cap, printable-ratio check, and only pure base64 blobs
    (no scheme URIs visible, base64 alphabet only) are decoded. Handles both
    one-big-blob and line-per-node subscription layouts.
    """
    found = set(NODE_RE.findall(text))
    if depth >= MAX_B64_DEPTH:
        return found

    # Whole-text blob (a single base64 subscription).
    stripped = text.strip()
    if len(stripped) >= BLOB_MIN_LEN and not NODE_RE.search(stripped) and B64_RE.match(stripped):
        decoded = _try_b64_decode(stripped)
        if decoded:
            found |= recursive_b64_nodes(decoded, depth + 1)

    # Line-oriented blobs (each line is its own base64 node/subscription).
    # No ">1 lines" gate: when only one line survives the length filter while
    # whole-text decoding fails, that single line still deserves a decode.
    for line in text.splitlines():
        line = line.strip()
        if len(line) < BLOB_MIN_LEN or NODE_RE.search(line) or not B64_RE.match(line):
            continue
        decoded = _try_b64_decode(line)
        if decoded:
            found |= recursive_b64_nodes(decoded, depth + 1)
    return found


# best-match ordering is near-static for a fixed query, so a single query
# re-fetches the same files every run. Multiple queries widen the water source.
DEFAULT_QUERIES = (
    "vmess extension:txt",
    "vless extension:txt",
    "trojan extension:txt",
    "subscription extension:txt",
)
SEARCH_INTERVAL = 7  # /search/code is capped at 10 req/min - stay well under it


def _resolve_queries() -> list[str]:
    """GITHUB_QUERIES override or defaults. Uses `or`, NOT getenv default:
    GitHub Actions passes unset vars.* through as EMPTY STRINGS, which would
    bypass a getenv default and silently disable the radar."""
    raw = os.getenv("GITHUB_QUERIES") or ",".join(DEFAULT_QUERIES)
    return [q.strip() for q in raw.split(",") if q.strip()]


def github_radar(session: requests.Session, token: str) -> set[str]:
    if not token:
        LOG.warning("GITHUB_TOKEN not set - GitHub radar skipped entirely.")
        return set()

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    # NOTE: /search/code does NOT support sort=updated (best-match only).
    # Recency is enforced by the history.txt diff downstream, not by the API.
    queries = _resolve_queries()
    if not queries:
        LOG.warning("GITHUB_QUERIES resolved to an empty list - radar disabled.")
        return set()
    LOG.info("GitHub radar: %d queries: %s", len(queries), queries)

    nodes: set[str] = set()
    seen_files: set[str] = set()
    raw_headers = {"Accept": "application/vnd.github.raw"}
    for idx, query in enumerate(queries):
        if idx:
            time.sleep(SEARCH_INTERVAL)
        params = {"q": query, "per_page": 50}
        resp = github_get(session, f"{GITHUB_API}/search/code", headers=headers, params=params)
        if resp.status_code != 200:
            LOG.warning("GitHub code search %r failed: HTTP %d - %s",
                        query, resp.status_code, resp.text[:200])
            continue
        try:
            items = resp.json().get("items", [])
        except ValueError:
            LOG.warning("GitHub code search returned non-JSON body for %r.", query)
            continue
        new_items = [it for it in items if it.get("url") and it["url"] not in seen_files]
        seen_files.update(it["url"] for it in new_items)
        LOG.info("GitHub radar: query %r -> %d files (%d new to this run)",
                 query, len(items), len(new_items))

        for item in new_items:
            if item.get("size", 0) > MAX_RAW_FILE_BYTES:
                continue
            try:
                raw = github_get(session, item["url"], headers=raw_headers)
            except requests.RequestException as exc:
                LOG.warning("Raw fetch failed for %s: %s", item.get("html_url", "?"), exc)
                continue
            if raw.status_code != 200:
                continue
            content = raw.content.decode("utf-8", errors="replace")
            nodes |= recursive_b64_nodes(content)
        LOG.info("GitHub radar: running total after %r: %d nodes", query, len(nodes))
    return nodes


# --------------------------------------------------------------------------
# Step 4 - concurrent TCP liveness check
# --------------------------------------------------------------------------

def _split_hostport(netloc: str) -> tuple[str, int] | None:
    """Parse host:port, including bracketed IPv6 like [2001:db8::1]:443."""
    netloc = netloc.strip()
    if not netloc:
        return None
    if netloc.startswith("["):
        host, _, rest = netloc[1:].partition("]")
        if not rest.startswith(":"):
            return None
        port = rest[1:]
    else:
        host, sep, port = netloc.rpartition(":")
        if not sep:
            return None
    try:
        return host.strip("[]"), int(port)
    except ValueError:
        return None


def _b64_segment(segment: str) -> bytes | None:
    stripped = re.sub(r"\s+", "", segment.split("#", 1)[0].split("?", 1)[0])
    if not stripped:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    for candidate in (padded, padded.translate(str.maketrans("-_", "+/"))):
        try:
            return base64.b64decode(candidate, validate=False)
        except (binascii.Error, ValueError):
            continue
    return None


def extract_endpoint(uri: str) -> tuple[str, int] | None:
    """Best-effort host/port extraction per protocol family."""
    scheme, _, rest = uri.partition("://")
    scheme = scheme.lower()

    if scheme == "vmess":  # base64 JSON: {"add": ..., "port": ...}
        raw = _b64_segment(rest)
        if not raw:
            return None
        try:
            info = json.loads(raw.decode("utf-8"))
            return str(info["add"]).strip("[]"), int(info["port"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return None

    if scheme == "ssr":  # base64 host:port:protocol:method:obfs:password/?params
        raw = _b64_segment(rest)
        if not raw:
            return None
        try:
            parts = raw.decode("utf-8").split(":")
            if len(parts) >= 2:
                return parts[0].strip("[]"), int(parts[1])
        except (ValueError, UnicodeDecodeError):
            return None
        return None

    if scheme == "ss":  # SIP002 userinfo@host:port, or legacy whole-blob base64
        netloc = rest.split("?", 1)[0].split("#", 1)[0]
        if "@" in netloc:
            return _split_hostport(netloc.rsplit("@", 1)[-1])
        raw = _b64_segment(netloc)  # legacy: base64(method:pass@host:port)
        if raw:
            try:
                return _split_hostport(raw.decode("utf-8").rsplit("@", 1)[-1])
            except UnicodeDecodeError:
                return None
        return None

    if scheme in ("vless", "trojan", "hysteria2", "hy2", "tuic"):
        netloc = rest.split("?", 1)[0].split("#", 1)[0]
        return _split_hostport(netloc.rsplit("@", 1)[-1])

    return None


def check_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:  # covers DNS failure, refused, timeout
        return False


def liveness_filter(uris: list[str]) -> tuple[list[str], int, int]:
    """Returns (sorted alive URIs, dead count, unparsable count)."""
    endpoints: dict[str, tuple[str, int]] = {}
    unparsed = 0
    for uri in uris:
        endpoint = extract_endpoint(uri)
        if endpoint is None:
            unparsed += 1
        else:
            endpoints[uri] = endpoint

    workers = max(1, min(256, int(os.getenv("ALIVE_WORKERS", "64"))))
    alive: list[str] = []
    dead = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="probe") as pool:
        futures = {pool.submit(check_tcp, host, port): uri
                   for uri, (host, port) in endpoints.items()}
        for future in as_completed(futures):
            if future.result():
                alive.append(futures[future])
            else:
                dead += 1
    return sorted(alive), dead, unparsed


# --------------------------------------------------------------------------
# Step 3 - incremental history (dedup pool)
# --------------------------------------------------------------------------

def load_history() -> set[str]:
    if not HISTORY_FILE.exists():
        HISTORY_FILE.touch()
        LOG.info("history.txt not found - created empty file.")
    known = {line.strip() for line in
             HISTORY_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
             if line.strip()}
    LOG.info("history.txt: %d known nodes on record", len(known))
    return known


def append_history(fresh: list[str]) -> None:
    with HISTORY_FILE.open("a", encoding="utf-8") as fh:
        for uri in sorted(fresh):
            fh.write(uri + "\n")


def load_previous_alive() -> set[str]:
    """Previous run's verified-alive list - re-checked each run so the
    subscription never freezes on a dying node set."""
    if not NODES_FILE.exists():
        return set()
    prev = {ln.strip() for ln in
            NODES_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()}
    LOG.info("Previous output: %d nodes to re-verify", len(prev))
    return prev


def write_outputs(alive: list[str]) -> None:
    payload = "\n".join(alive) + ("\n" if alive else "")
    NODES_FILE.write_text(payload, encoding="utf-8")
    SUB_FILE.write_text(
        base64.b64encode(payload.encode("utf-8")).decode("ascii") + "\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    token = os.getenv("GITHUB_TOKEN", "")
    channels = [c.strip() for c in (os.getenv("RSS_CHANNELS") or "v2raypro").split(",") if c.strip()]
    LOG.info("Channels: %s | RSSHub bases: %s | GitHub radar: %s",
             channels, RSSHUB_BASES, "ON" if token else "OFF")

    session = make_session(token or None)

    candidates: set[str] = set()
    candidates |= fetch_rsshub(session, channels)
    candidates |= github_radar(session, token)
    LOG.info("Total candidates before dedup: %d", len(candidates))

    if not candidates:
        # Abort instead of wiping outputs / flooding history with nothing.
        LOG.error("Both sources returned zero nodes - aborting, outputs untouched.")
        return 1

    history = load_history()
    fresh = sorted(candidates - history)
    LOG.info("New nodes after diff against history: %d", len(fresh))

    prev_alive = load_previous_alive()
    if not fresh and not prev_alive:
        LOG.info("Nothing new and no previous list - done.")
        return 0

    # Rolling alive pool: new survivors + re-verified previous survivors.
    alive_new: list[str] = []
    dead_new = unparsed_new = 0
    if fresh:
        alive_new, dead_new, unparsed_new = liveness_filter(fresh)
        LOG.info("Liveness(fresh): %d alive / %d dead / %d unparsable",
                 len(alive_new), dead_new, unparsed_new)

    alive_prev: list[str] = []
    if prev_alive:
        alive_prev, dead_prev, _ = liveness_filter(sorted(prev_alive))
        LOG.info("Liveness(previous): %d still alive / %d now dead",
                 len(alive_prev), dead_prev)

    alive = sorted(set(alive_new) | set(alive_prev))
    if alive:
        write_outputs(alive)
        LOG.info("Wrote %d alive nodes to %s (+ base64 sub to %s) "
                 "[%d fresh + %d retained]",
                 len(alive), NODES_FILE.name, SUB_FILE.name,
                 len(alive_new), len(alive_prev))
    elif prev_alive:
        # Everything died - an honest empty list beats a frozen corpse list.
        write_outputs([])
        LOG.warning("All %d previous nodes are now dead - outputs reset to empty.",
                    len(prev_alive))

    append_history(fresh)  # every fresh node goes on record, dead or not
    LOG.info("history.txt updated: +%d entries.", len(fresh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
