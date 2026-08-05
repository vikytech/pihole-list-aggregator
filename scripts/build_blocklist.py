#!/usr/bin/env python3
"""
Aggregate multiple blocklists into one Pi-hole v6-compatible list.

The parser intentionally follows the accepted formats in the current Pi-hole
FTL gravity parser:

  * exact domains, including HOSTS-style files
  * ABP-style blocking entries in the exact form: ||domain^

Other ABP syntax (options, paths, cosmetic rules, redirects, scriptlets, etc.)
is not a Pi-hole gravity domain entry and is intentionally discarded.

Outputs:
  build/pihole.txt   Combined exact-domain and ABP-domain list for Pi-hole
  build/domains.txt  Exact domains only
  build/abp.txt      Supported ABP-style blocking domains only
  build/stats.json   Per-source and aggregate statistics
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

USER_AGENT = "pihole-v6-blocklist-aggregator/2.0 (+GitHub Actions)"

# Pi-hole FTL accepts these characters in a domain token.
VALID_DOMAIN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
)

# Matches the harmless local-host tokens Pi-hole suppresses from invalid output.
FALSE_POSITIVES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "lo0",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
}


@dataclass
class SourceStats:
    url: str
    status: str = "failed"
    downloaded_bytes: int = 0
    exact_entries_seen: int = 0
    abp_entries_seen: int = 0
    unique_exact_entries: int = 0
    unique_abp_entries: int = 0
    ignored_entries: int = 0
    error: str | None = None


def read_sources(path: Path) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            urls.append(line)
            seen.add(line)

    if not urls:
        raise ValueError(f"No source URLs found in {path}")
    return urls


def fetch(url: str, timeout: int, retries: int) -> bytes:
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/plain,*/*;q=0.8",
                },
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2**attempt)

    assert last_error is not None
    raise last_error


def valid_domain(domain: str, *, fqdn_only: bool) -> bool:
    """
    Mirror Pi-hole FTL's gravity domain validation closely.

    Notes:
      * maximum length is 255
      * accepted characters are A-Z, a-z, 0-9, dot, hyphen and underscore
      * labels must be non-empty and at most 63 characters
      * exact domains require at least one dot
      * ABP domain bodies may be single-label
      * the final label may not start or end with a hyphen
    """
    length = len(domain)
    if length == 0 or length > 255:
        return False
    if any(char not in VALID_DOMAIN_CHARS for char in domain):
        return False

    labels = domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if fqdn_only and len(labels) < 2:
        return False
    if labels[-1].startswith("-") or labels[-1].endswith("-"):
        return False

    return True


def valid_abp_blocking_rule(token: str) -> bool:
    # Current Pi-hole blocking-list syntax is exactly: ||domain^
    return (
        len(token) >= 3
        and token.startswith("||")
        and token.endswith("^")
        and valid_domain(token[2:-1], fqdn_only=False)
    )


def is_ip_address(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def parse_pihole_compatible(text: str) -> tuple[set[str], set[str], int, int, int]:
    """
    Return:
      exact domains,
      ABP blocking rules,
      number of exact entries seen,
      number of ABP entries seen,
      number of ignored/invalid tokens
    """
    exact: set[str] = set()
    abp: set[str] = set()
    exact_seen = 0
    abp_seen = 0
    ignored = 0

    # Pi-hole removes a UTF-8 BOM only from the start of the file.
    if text.startswith("\ufeff"):
        text = text[1:]

    for raw_line in text.splitlines():
        # Pi-hole trims trailing whitespace, not leading whitespace.
        line = raw_line.rstrip()
        if not line:
            continue

        # Current gravity parser comment/header handling.
        if line[0] in ("!", "#", ";", "["):
            continue

        # Skip ABP extended CSS and AdGuard JavaScript rules.
        hash_pos = line.find("#")
        if hash_pos > 0 and hash_pos + 1 < len(line):
            if line[hash_pos + 1] in ("#", "$", "@", "?", "%"):
                continue

        # Strip shell/hosts-style inline comments.
        if "#" in line:
            line = line.split("#", 1)[0]
        if not line:
            continue

        # Pi-hole checks every whitespace-separated token. This supports
        # HOSTS files such as "0.0.0.0 example.com another.example".
        for token in line.split():
            if not token:
                continue
            if is_ip_address(token):
                continue

            if token.endswith("."):
                token = token[:-1]
            if not token:
                continue

            token = token.lower()

            if valid_domain(token, fqdn_only=True):
                exact_seen += 1
                exact.add(token)
            elif valid_abp_blocking_rule(token):
                abp_seen += 1
                abp.add(token)
            elif token not in FALSE_POSITIVES:
                ignored += 1

    return exact, abp, exact_seen, abp_seen, ignored


def process_source(
    url: str, timeout: int, retries: int
) -> tuple[SourceStats, set[str], set[str]]:
    stats = SourceStats(url=url)

    try:
        payload = fetch(url, timeout=timeout, retries=retries)
        stats.downloaded_bytes = len(payload)

        # utf-8-sig also safely handles BOMs, while replacement prevents one
        # malformed byte from discarding an otherwise usable source.
        text = payload.decode("utf-8-sig", errors="replace")
        exact, abp, exact_seen, abp_seen, ignored = parse_pihole_compatible(text)

        stats.exact_entries_seen = exact_seen
        stats.abp_entries_seen = abp_seen
        stats.unique_exact_entries = len(exact)
        stats.unique_abp_entries = len(abp)
        stats.ignored_entries = ignored
        stats.status = "ok"
        return stats, exact, abp
    except Exception as exc:
        stats.error = f"{type(exc).__name__}: {exc}"
        return stats, set(), set()


def write_outputs(
    output_dir: Path,
    exact: set[str],
    abp: set[str],
    source_stats: list[SourceStats],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    ordered_exact = sorted(exact)
    ordered_abp = sorted(abp)

    exact_header = (
        "# Aggregated Pi-hole exact-domain blocklist\n"
        "# Generated automatically; do not edit manually.\n"
        f"# Unique exact domains: {len(ordered_exact)}\n"
    )
    abp_header = (
        "# Aggregated Pi-hole-supported ABP blocklist\n"
        "# Only rules in the exact form ||domain^ are included.\n"
        f"# Unique ABP rules: {len(ordered_abp)}\n"
    )
    combined_header = (
        "# Aggregated and deduplicated Pi-hole v6 gravity list\n"
        "# Contains exact domains and supported ABP rules (||domain^).\n"
        f"# Unique exact domains: {len(ordered_exact)}\n"
        f"# Unique ABP rules: {len(ordered_abp)}\n"
        f"# Total unique entries: {len(ordered_exact) + len(ordered_abp)}\n"
    )

    (output_dir / "domains.txt").write_text(
        exact_header + "\n".join(ordered_exact) + "\n",
        encoding="utf-8",
    )
    (output_dir / "abp.txt").write_text(
        abp_header + "\n".join(ordered_abp) + "\n",
        encoding="utf-8",
    )
    (output_dir / "pihole.txt").write_text(
        combined_header
        + "\n".join(ordered_exact)
        + "\n"
        + "\n".join(ordered_abp)
        + "\n",
        encoding="utf-8",
    )

    report = {
        "unique_exact_domains": len(ordered_exact),
        "unique_abp_rules": len(ordered_abp),
        "total_unique_entries": len(ordered_exact) + len(ordered_abp),
        "successful_sources": sum(s.status == "ok" for s in source_stats),
        "failed_sources": sum(s.status != "ok" for s in source_stats),
        "sources": [asdict(s) for s in source_stats],
    }
    (output_dir / "stats.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=Path("sources.txt"))
    parser.add_argument("--output", type=Path, default=Path("build"))
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument(
        "--minimum-entries",
        type=int,
        default=10_000,
        help="Refuse to publish an unexpectedly small combined list.",
    )
    parser.add_argument(
        "--max-failed-sources",
        type=int,
        default=5,
        help="Refuse to publish if more than this many sources fail.",
    )
    args = parser.parse_args()

    urls = read_sources(args.sources)
    results: list[tuple[SourceStats, set[str], set[str]]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_source, url, args.timeout, args.retries): url
            for url in urls
        }
        for future in concurrent.futures.as_completed(futures):
            stats, exact, abp = future.result()
            results.append((stats, exact, abp))

            marker = "OK" if stats.status == "ok" else "FAILED"
            print(
                f"[{marker}] {stats.url} -> "
                f"{stats.unique_exact_entries:,} exact, "
                f"{stats.unique_abp_entries:,} ABP"
            )
            if stats.error:
                print(f"         {stats.error}", file=sys.stderr)

    order = {url: index for index, url in enumerate(urls)}
    results.sort(key=lambda item: order[item[0].url])

    all_exact: set[str] = set()
    all_abp: set[str] = set()
    all_stats: list[SourceStats] = []

    for stats, exact, abp in results:
        all_stats.append(stats)
        all_exact.update(exact)
        all_abp.update(abp)

    failed = sum(s.status != "ok" for s in all_stats)
    if failed > args.max_failed_sources:
        print(
            f"Refusing to publish: {failed} sources failed "
            f"(maximum allowed: {args.max_failed_sources}).",
            file=sys.stderr,
        )
        return 1

    total = len(all_exact) + len(all_abp)
    if total < args.minimum_entries:
        print(
            f"Refusing to publish only {total:,} entries "
            f"(minimum: {args.minimum_entries:,}).",
            file=sys.stderr,
        )
        return 1

    write_outputs(args.output, all_exact, all_abp, all_stats)
    print(
        f"Published {len(all_exact):,} exact domains and "
        f"{len(all_abp):,} ABP rules ({total:,} total)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
