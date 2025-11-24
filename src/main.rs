use bgpkit_parser::{BgpkitParser, models::ElemType};
use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::{IpNet as IpRangeNet, IpRange, ToNetwork};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "bgptools")]
struct Opts {
    #[arg(short, long, value_name = "MRT", default_value = "./rib")]
    mrt_file: PathBuf,

    #[arg(value_name = "ASN", value_parser = clap::value_parser!(u32), num_args = 1..)]
    asns: Vec<u32>,
}

#[derive(Default)]
struct PrefixBuckets {
    included_v4: Vec<Ipv4Net>,
    included_v6: Vec<Ipv6Net>,
    excluded_v4: Vec<Ipv4Net>,
    excluded_v6: Vec<Ipv6Net>,
}

impl PrefixBuckets {
    fn record(&mut self, net: IpNet, has_included_origin: bool) {
        match (net, has_included_origin) {
            (IpNet::V4(prefix), true) => self.included_v4.push(prefix),
            (IpNet::V6(prefix), true) => self.included_v6.push(prefix),
            (IpNet::V4(prefix), false) => self.excluded_v4.push(prefix),
            (IpNet::V6(prefix), false) => self.excluded_v6.push(prefix),
        }
    }

    fn finalize(self) -> (IpRange<Ipv4Net>, IpRange<Ipv6Net>) {
        fn filter_range<N>(included: Vec<N>, excluded: Vec<N>) -> IpRange<N>
        where
            N: IpRangeNet + ToNetwork<N> + Clone + Ord + Eq + std::hash::Hash,
        {
            fn dedup<N: Eq + std::hash::Hash + Clone>(nets: Vec<N>) -> Vec<N> {
                let mut seen = HashSet::new();
                let mut uniq = Vec::new();
                for net in nets {
                    if seen.insert(net.clone()) {
                        uniq.push(net);
                    }
                }
                uniq
            }

            let included = dedup(included);
            let excluded = dedup(excluded);

            let mut aggregate = IpRange::new();
            for inc in included {
                let mut working = IpRange::new();
                let inc_len = inc.prefix_len();
                working.add(inc.clone());

                for exc in &excluded {
                    if exc.prefix_len() <= inc_len {
                        continue;
                    }
                    if working.is_empty() {
                        break;
                    }
                    working.remove(exc.clone());
                }

                for net in working.iter() {
                    aggregate.add(net.clone());
                }
            }

            aggregate.simplify();
            aggregate
        }

        let PrefixBuckets {
            included_v4,
            included_v6,
            excluded_v4,
            excluded_v6,
        } = self;

        let filtered_v4 = filter_range(included_v4, excluded_v4);
        let filtered_v6 = filter_range(included_v6, excluded_v6);
        (filtered_v4, filtered_v6)
    }
}

fn main() {
    let opts: Opts = Opts::parse();
    let asn_list: HashSet<u32> = opts.asns.into_iter().collect();

    let rib_path = opts.mrt_file.to_string_lossy().into_owned();
    let parser =
        BgpkitParser::new(rib_path.as_str()).expect("failed to open MRT/RIB file with bgpkit");

    let mut buckets = PrefixBuckets::default();

    for elem in parser.into_elem_iter() {
        if !matches!(elem.elem_type, ElemType::ANNOUNCE) {
            continue;
        }

        let origins = match &elem.origin_asns {
            Some(origins) => origins,
            None => continue,
        };

        let net = match elem.prefix.to_string().parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => continue,
        };

        let has_included_origin = origins
            .iter()
            .any(|asn| asn_list.contains(&asn.to_u32()));

        buckets.record(net, has_included_origin);
    }

    let (filtered_v4, filtered_v6) = buckets.finalize();

    emit_sorted(&filtered_v4);
    emit_sorted(&filtered_v6);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_more_specific_from_supernet() {
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![Ipv4Net::from_str("10.0.0.0/23").unwrap()],
            included_v6: Vec::new(),
            excluded_v4: vec![Ipv4Net::from_str("10.0.0.0/24").unwrap()],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let nets: Vec<Ipv4Net> = filtered_v4.iter().collect();

        assert_eq!(nets, vec![Ipv4Net::from_str("10.0.1.0/24").unwrap()]);
    }

    #[test]
    fn excludes_more_specific_overlap() {
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let mut buckets = PrefixBuckets::default();
        buckets
            .included_v4
            .push(Ipv4Net::from_str("223.64.0.0/10").unwrap());
        buckets
            .excluded_v4
            .push(Ipv4Net::from_str("223.122.128.0/17").unwrap());

        let (filtered_v4, _) = buckets.finalize();
        let overlap = Ipv4Addr::from_str("223.122.128.1").unwrap();

        assert!(
            filtered_v4
                .iter()
                .all(|net| !net.contains(&overlap)),
            "filtered output still covers the excluded address"
        );
    }

    #[test]
    fn per_include_removal_leaves_gap() {
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![Ipv4Net::from_str("10.0.0.0/8").unwrap()],
            included_v6: Vec::new(),
            excluded_v4: vec![Ipv4Net::from_str("10.0.0.0/24").unwrap()],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let missing = Ipv4Addr::new(10, 0, 0, 1);
        let present = Ipv4Addr::new(10, 0, 2, 1);

        assert!(
            !filtered_v4.iter().any(|net| net.contains(&missing)),
            "gap address should be removed"
        );
        assert!(
            filtered_v4.iter().any(|net| net.contains(&present)),
            "non-overlapping address should remain"
        );
    }

    #[test]
    fn excludes_only_matching_length_in_ipv6() {
        use std::str::FromStr;

        let included = vec![
            Ipv6Net::from_str("2001:db8::/48").unwrap(),
            Ipv6Net::from_str("2001:db8:1::/48").unwrap(),
        ];
        let excluded = vec![Ipv6Net::from_str("2001:db8:1::/64").unwrap()];

        let buckets = PrefixBuckets {
            included_v4: Vec::new(),
            included_v6: included,
            excluded_v4: Vec::new(),
            excluded_v6: excluded,
        };

        let (_, filtered_v6) = buckets.finalize();
        let nets: Vec<Ipv6Net> = filtered_v6.iter().collect();

        assert!(
            nets.iter()
                .any(|net| net == &Ipv6Net::from_str("2001:db8::/48").unwrap()),
            "first include should stay untouched"
        );
        assert!(
            nets.iter().all(|net| !net.contains(&std::net::Ipv6Addr::from(0x20010db800010000u128))),
            "the excluded /64 should be fully stripped"
        );
    }

    #[test]
    fn exclude_same_as_include_is_ignored() {
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![Ipv4Net::from_str("192.0.2.0/24").unwrap()],
            included_v6: Vec::new(),
            excluded_v4: vec![Ipv4Net::from_str("192.0.2.0/24").unwrap()],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let nets: Vec<Ipv4Net> = filtered_v4.iter().collect();
        assert_eq!(nets, vec![Ipv4Net::from_str("192.0.2.0/24").unwrap()]);
    }

    #[test]
    fn duplicated_entries_are_deduplicated() {
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![
                Ipv4Net::from_str("198.51.100.0/24").unwrap(),
                Ipv4Net::from_str("198.51.100.0/24").unwrap(),
            ],
            included_v6: Vec::new(),
            excluded_v4: vec![
                Ipv4Net::from_str("198.51.100.0/25").unwrap(),
                Ipv4Net::from_str("198.51.100.0/25").unwrap(),
            ],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let nets: Vec<Ipv4Net> = filtered_v4.iter().collect();

        assert_eq!(nets.len(), 1);
        assert!(
            nets.contains(&Ipv4Net::from_str("198.51.100.128/25").unwrap()),
            "only upper half should remain"
        );
    }

    #[test]
    fn overlapping_excludes_are_applied_sequentially() {
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![Ipv4Net::from_str("100.64.0.0/10").unwrap()],
            included_v6: Vec::new(),
            excluded_v4: vec![
                Ipv4Net::from_str("100.64.0.0/11").unwrap(),
                Ipv4Net::from_str("100.96.0.0/11").unwrap(),
            ],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        assert!(filtered_v4.is_empty());
    }

    #[test]
    fn exclude_supernet_removes_multiple_includes() {
        use std::str::FromStr;

        let buckets = PrefixBuckets {
            included_v4: vec![
                Ipv4Net::from_str("203.0.113.0/25").unwrap(),
                Ipv4Net::from_str("203.0.113.128/25").unwrap(),
            ],
            included_v6: Vec::new(),
            excluded_v4: vec![Ipv4Net::from_str("203.0.113.0/24").unwrap()],
            excluded_v6: Vec::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let nets: Vec<Ipv4Net> = filtered_v4.iter().collect();
        assert_eq!(nets, vec![Ipv4Net::from_str("203.0.113.0/24").unwrap()]);
    }
}