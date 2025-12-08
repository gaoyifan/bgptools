use bgpkit_parser::{BgpkitParser, models::ElemType};
use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv4Subnets, Ipv6Net, Ipv6Subnets};
use iprange::{IpNet as IpRangeNet, IpRange, ToNetwork};
use prefix_trie::PrefixMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use vec_collections::VecSet;

type AsnRangesV4 = HashMap<u32, IpRange<Ipv4Net>>;
type AsnRangesV6 = HashMap<u32, IpRange<Ipv6Net>>;

fn is_private_asn(asn: u32) -> bool {
    (64512..=65534).contains(&asn) || (4_200_000_000..=4_294_967_294).contains(&asn)
}

#[derive(Parser, Debug)]
#[command(name = "bgptools", version)]
struct Opts {
    #[arg(short, long, value_name = "MRT", default_value = "./rib")]
    mrt_file: PathBuf,

    #[arg(value_name = "ASN", value_parser = clap::value_parser!(u32), num_args = 1..)]
    asns: Vec<u32>,

    #[arg(long, default_value_t = false)]
    ignore_private_asn: bool,

    #[arg(long, value_name = "CACHE")]
    cache: Option<PathBuf>,
}

fn main() {
    let Opts {
        mrt_file,
        asns,
        ignore_private_asn,
        cache,
    } = Opts::parse();
    let asn_list: HashSet<u32> = asns.into_iter().collect();

    let (asn_ranges_v4, asn_ranges_v6) = cache
        .as_deref()
        .and_then(|path| load_cache(path, ignore_private_asn))
        .unwrap_or_else(|| {
            let (v4, v6) = build_asn_ranges(&mrt_file, ignore_private_asn);
            if let Some(path) = cache.as_deref() {
                let cached = CachedRanges {
                    ignore_private_asn,
                    v4,
                    v6,
                };
                let CachedRanges { v4, v6, .. } = save_cache(path, cached);
                (v4, v6)
            } else {
                (v4, v6)
            }
        });

    let mut result_v4: IpRange<Ipv4Net> = IpRange::new();
    let mut result_v6: IpRange<Ipv6Net> = IpRange::new();

    // Step 5: Filter and merge IP ranges for target ASNs
    for asn in &asn_list {
        if let Some(range) = asn_ranges_v4.get(asn) {
            for net in range.iter() {
                result_v4.add(net);
            }
        }
        if let Some(range) = asn_ranges_v6.get(asn) {
            for net in range.iter() {
                result_v6.add(net);
            }
        }
    }

    result_v4.simplify();
    result_v6.simplify();

    emit_sorted(&result_v4);
    emit_sorted(&result_v6);
}

/// Convert an IP interval [start, end) to a list of CIDR prefixes.
fn interval_to_cidrs_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Net> {
    if start >= end {
        return Vec::new();
    }

    let end_inclusive = u32::from(end).saturating_sub(1);
    Ipv4Subnets::new(start, Ipv4Addr::from(end_inclusive), 0).collect()
}

/// Convert an IP interval [start, end) to a list of CIDR prefixes.
fn interval_to_cidrs_v6(start: Ipv6Addr, end: Ipv6Addr) -> Vec<Ipv6Net> {
    if start >= end {
        return Vec::new();
    }

    let end_inclusive = u128::from(end).saturating_sub(1);
    Ipv6Subnets::new(start, Ipv6Addr::from(end_inclusive), 0).collect()
}

fn emit_sorted<N>(range: &IpRange<N>)
where
    N: IpRangeNet + ToNetwork<N> + Clone + Ord + std::fmt::Display,
{
    let mut nets: Vec<N> = range.iter().collect();
    nets.sort_unstable();
    for net in nets {
        println!("{}", net);
    }
}

#[derive(Serialize, Deserialize)]
struct CachedRanges {
    ignore_private_asn: bool,
    v4: AsnRangesV4,
    v6: AsnRangesV6,
}

fn load_cache(path: &Path, ignore_private_asn: bool) -> Option<(AsnRangesV4, AsnRangesV6)> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let cache: CachedRanges = bincode::deserialize_from(reader).ok()?;
    if cache.ignore_private_asn == ignore_private_asn {
        Some((cache.v4, cache.v6))
    } else {
        None
    }
}

fn save_cache(path: &Path, cache: CachedRanges) -> CachedRanges {
    if let Ok(file) = File::create(path) {
        let writer = BufWriter::new(file);
        let _ = bincode::serialize_into(writer, &cache);
    }
    cache
}

fn build_asn_ranges(mrt_file: &Path, ignore_private_asn: bool) -> (AsnRangesV4, AsnRangesV6) {
    let rib_path = mrt_file.to_string_lossy().into_owned();
    let parser =
        BgpkitParser::new(rib_path.as_str()).expect("failed to open MRT/RIB file with bgpkit");

    // Step 1: Build PrefixMap<CIDR, VecSet<origin_asn>>
    let mut prefix_map_v4: PrefixMap<Ipv4Net, VecSet<[u32; 4]>> = PrefixMap::new();
    let mut prefix_map_v6: PrefixMap<Ipv6Net, VecSet<[u32; 4]>> = PrefixMap::new();

    // Step 2: Collect candidate split points
    let mut split_points_v4_set: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut split_points_v6_set: BTreeSet<Ipv6Addr> = BTreeSet::new();

    for elem in parser.into_elem_iter() {
        if !matches!(elem.elem_type, ElemType::ANNOUNCE) {
            continue;
        }

        let origins = match &elem.origin_asns {
            Some(origins) => origins,
            None => continue,
        };

        if ignore_private_asn && origins.iter().any(|asn| is_private_asn(asn.to_u32())) {
            continue;
        }

        let origin_asns: HashSet<u32> = origins.iter().map(|asn| asn.to_u32()).collect();

        match elem.prefix.prefix {
            IpNet::V4(net) => {
                // Insert into prefix map
                prefix_map_v4.entry(net).or_default().extend(origin_asns);

                // Collect split points
                split_points_v4_set.insert(net.network());
                u32::from(net.broadcast())
                    .checked_add(1)
                    .map(Ipv4Addr::from)
                    .map(|e| split_points_v4_set.insert(e));
            }
            IpNet::V6(net) => {
                // Insert into prefix map
                prefix_map_v6.entry(net).or_default().extend(origin_asns);

                // Collect split points
                split_points_v6_set.insert(net.network());
                u128::from(net.broadcast())
                    .checked_add(1)
                    .map(Ipv6Addr::from)
                    .map(|e| split_points_v6_set.insert(e));
            }
        }
    }

    // Step 3: Sort split points (BTreeSet already keeps them sorted)
    let split_points_v4: Vec<Ipv4Addr> = split_points_v4_set.into_iter().collect();
    let split_points_v6: Vec<Ipv6Addr> = split_points_v6_set.into_iter().collect();

    // Step 4: Build origin-AS to IP range mapping
    let mut asn_ranges_v4: AsnRangesV4 = HashMap::new();
    let mut asn_ranges_v6: AsnRangesV6 = HashMap::new();

    // Process IPv4 split points
    for i in 0..split_points_v4.len().saturating_sub(1) {
        let start = split_points_v4[i];
        let end = split_points_v4[i + 1];

        // Look up origin ASNs at this exact address using longest prefix match
        let lookup_prefix = Ipv4Net::new(start, 32).unwrap();
        if let Some((_, asns)) = prefix_map_v4.get_lpm(&lookup_prefix) {
            // For each origin ASN, add this interval
            for &asn in asns {
                // Convert interval [start, end) to CIDR ranges
                let nets = interval_to_cidrs_v4(start, end);
                let range = asn_ranges_v4.entry(asn).or_insert_with(IpRange::new);
                for net in nets {
                    range.add(net);
                }
            }
        }
    }

    // Process IPv6 split points
    for i in 0..split_points_v6.len().saturating_sub(1) {
        let start = split_points_v6[i];
        let end = split_points_v6[i + 1];

        // Look up origin ASNs at this exact address using longest prefix match
        let lookup_prefix = Ipv6Net::new(start, 128).unwrap();
        if let Some((_, asns)) = prefix_map_v6.get_lpm(&lookup_prefix) {
            // For each origin ASN, add this interval
            for &asn in asns {
                // Convert interval [start, end) to CIDR ranges
                let nets = interval_to_cidrs_v6(start, end);
                let range = asn_ranges_v6.entry(asn).or_insert_with(IpRange::new);
                for net in nets {
                    range.add(net);
                }
            }
        }
    }

    (asn_ranges_v4, asn_ranges_v6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_interval_to_cidrs_v4_simple() {
        let start = Ipv4Addr::from_str("192.168.0.0").unwrap();
        let end = Ipv4Addr::from_str("192.168.1.0").unwrap();
        let cidrs = interval_to_cidrs_v4(start, end);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0], Ipv4Net::from_str("192.168.0.0/24").unwrap());
    }

    #[test]
    fn test_interval_to_cidrs_v4_complex() {
        // [10.0.0.0, 10.0.2.0) should produce 10.0.0.0/23
        let start = Ipv4Addr::from_str("10.0.0.0").unwrap();
        let end = Ipv4Addr::from_str("10.0.2.0").unwrap();
        let cidrs = interval_to_cidrs_v4(start, end);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0], Ipv4Net::from_str("10.0.0.0/23").unwrap());
    }

    #[test]
    fn test_interval_to_cidrs_v4_unaligned() {
        // [10.0.1.0, 10.0.2.0) should produce 10.0.1.0/24
        let start = Ipv4Addr::from_str("10.0.1.0").unwrap();
        let end = Ipv4Addr::from_str("10.0.2.0").unwrap();
        let cidrs = interval_to_cidrs_v4(start, end);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0], Ipv4Net::from_str("10.0.1.0/24").unwrap());
    }

    #[test]
    fn test_interval_to_cidrs_v4_multiple() {
        // [10.0.1.0, 10.0.3.0) should produce 10.0.1.0/24, 10.0.2.0/24
        let start = Ipv4Addr::from_str("10.0.1.0").unwrap();
        let end = Ipv4Addr::from_str("10.0.3.0").unwrap();
        let cidrs = interval_to_cidrs_v4(start, end);
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&Ipv4Net::from_str("10.0.1.0/24").unwrap()));
        assert!(cidrs.contains(&Ipv4Net::from_str("10.0.2.0/24").unwrap()));
    }

    #[test]
    fn detects_private_asn_ranges() {
        assert!(is_private_asn(64512));
        assert!(is_private_asn(65534));
        assert!(is_private_asn(4_200_000_000));
        assert!(is_private_asn(4_294_967_294));
        assert!(!is_private_asn(64511));
        assert!(!is_private_asn(13335));
    }
}
