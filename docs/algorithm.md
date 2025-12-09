## Algorithm Overview

`bgptools` reads one or more MRT/RIB files and outputs the IPv4/IPv6 prefixes originated by the ASNs provided on the command line.

- Inputs: MRT file paths (`--mrt-file`), target ASNs (positional), `--ignore-private-asn`, and `--cache`.
- Output: Simplified, sorted list of CIDR prefixes (v4 then v6) for the requested ASNs.

## Processing Steps

1) **Parse MRT files (parallel)**  
   Each MRT file is parsed with `BgpkitParser`, keeping only ANNOUNCE records. For every prefix the code collects:
   - Origin ASNs (skipping private ASNs when requested).
   - AS path (truncated to last 4 hops).
   - Split points: prefix network address and the next address after the broadcast. These points mark boundaries for later interval construction.
   Results are stored separately for v4 and v6:
   - `prefix_map_*`: longest-prefix-match map of prefix → set of origin ASNs.
   - `as_paths_*`: prefix → origin ASN → list of truncated AS paths.
   - `split_points_*`: ordered set of addresses that delimit intervals.

2) **Merge per-file data**  
   Parsed structures are merged across files. Split points are deduped and sorted (via `BTreeSet`).

3) **Add shared upstream ASNs**  
   For each prefix, the algorithm computes the longest common suffix of the collected AS paths (capped to 4 ASNs). These shared upstream ASNs are added to the prefix map so they are treated like origin ASNs for interval attribution.

4) **Build ASN → IP ranges**  
   Consecutive split points define half-open intervals `[start, end)`. For each interval, a /32 (v4) or /128 (v6) lookup finds the longest covering prefix and its ASNs. Each ASN receives the interval, converted to a minimal set of CIDRs via `interval_to_cidrs_v4/v6`. The per-AS ranges are stored as `IpRange` structures to allow merging.

5) **Finalize result**  
   For the requested ASNs, the collected ranges are merged and simplified, then emitted in sorted order (v4 then v6).

## Caching

When `--cache` is enabled, the computed ASN→range maps are serialized to a bincode file keyed by input file list and `ignore_private_asn` flag. Subsequent runs reuse the cache when the key matches.

## Key Functions (in `src/main.rs`)

- `process_mrt_file`: Parses one MRT file and extracts prefix/ASN/path data plus split points.
- `longest_common_suffix`: Finds shared tail of AS paths (≤4 hops).
- `interval_to_cidrs_v4/v6`: Converts `[start, end)` intervals to minimal CIDR cover.
- `build_asn_ranges`: Orchestrates merging, shared-upstream attribution, interval slicing, and ASN range construction.
