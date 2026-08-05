# Pi-hole v6 aggregated blocklist

This repository downloads all sources in `sources.txt`, applies the same
domain-entry rules used by the current Pi-hole FTL gravity parser, deduplicates
the accepted entries, and publishes one combined list each day.

## Supported entries

The combined output keeps:

- exact domains, including domains extracted from HOSTS-style lines;
- Pi-hole-supported ABP blocking rules in the exact form `||domain^`.

It intentionally rejects unsupported browser-filter syntax such as:

- `@@||domain^` inside a normal blocking list;
- ABP options such as `||domain^$important`;
- URL/path filters;
- cosmetic filters such as `example.com##.advert`;
- scriptlets, redirects and extended CSS rules.

Pi-hole handles allow-list subscriptions separately as **antigravity** lists.
A normal blocking adlist must therefore not mix in `@@||domain^` entries.

## Generated files

- `build/pihole.txt` — use this URL in Pi-hole; contains exact + ABP entries.
- `build/domains.txt` — exact domains only.
- `build/abp.txt` — supported `||domain^` rules only.
- `build/stats.json` — counts and failures for every source.

## Setup

1. Create a public GitHub repository.
2. Upload this project, preserving the `.github` directory.
3. Run **Actions → Update Pi-hole blocklist → Run workflow** once.
4. Add this URL in Pi-hole:

   `https://raw.githubusercontent.com/vikytech/pihole-list-aggregator/main/build/pihole.txt`

5. Update Gravity.
6. Confirm the combined list works, then disable the original individual lists.

A private repository's raw URL is not anonymously readable by Pi-hole.

## Deduplication

Exact-domain strings are deduplicated globally. ABP-rule strings are also
deduplicated globally. The script does not perform aggressive semantic pruning
between exact and wildcard rules because that can alter list-maintainer intent.

## Local test and build

```bash
python -m unittest discover -s tests -v
python scripts/build_blocklist.py
```

## Safety checks

The workflow refuses to publish when:

- more than five sources fail; or
- the combined result unexpectedly falls below 10,000 entries.

You can change these thresholds through the command-line options in the
workflow.
