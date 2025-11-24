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
    included_v4: IpRange<Ipv4Net>,
    included_v6: IpRange<Ipv6Net>,
    excluded_v4: IpRange<Ipv4Net>,
    excluded_v6: IpRange<Ipv6Net>,
}

impl PrefixBuckets {
    fn record(&mut self, net: IpNet, has_included_origin: bool) {
        match (net, has_included_origin) {
            (IpNet::V4(prefix), true) => {
                self.included_v4.add(prefix);
            }
            (IpNet::V6(prefix), true) => {
                self.included_v6.add(prefix);
            }
            (IpNet::V4(prefix), false) => {
                self.excluded_v4.add(prefix);
            }
            (IpNet::V6(prefix), false) => {
                self.excluded_v6.add(prefix);
            }
        }
    }

    fn finalize(self) -> (IpRange<Ipv4Net>, IpRange<Ipv6Net>) {
        fn filter_range<N>(included: IpRange<N>, excluded: IpRange<N>) -> IpRange<N>
        where
            N: IpRangeNet + ToNetwork<N> + Clone,
        {
            let mut mask = IpRange::<N>::new();
            for net in excluded.iter() {
                if let Some(supernet) = included.supernet(&net) {
                    if supernet.prefix_len() < net.prefix_len() {
                        mask.add(net);
                    }
                }
            }

            let mut filtered = included.exclude(&mask);
            filtered.simplify();
            filtered
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
    fn retains_supernet_when_excluding_more_specific() {
        use std::str::FromStr;

        let mut included_v4 = IpRange::new();
        included_v4.add(Ipv4Net::from_str("10.0.0.0/24").unwrap());
        included_v4.add(Ipv4Net::from_str("10.0.1.0/24").unwrap());

        let mut excluded_v4 = IpRange::new();
        excluded_v4.add(Ipv4Net::from_str("10.0.0.0/24").unwrap());

        let buckets = PrefixBuckets {
            included_v4,
            included_v6: IpRange::new(),
            excluded_v4,
            excluded_v6: IpRange::new(),
        };

        let (filtered_v4, _) = buckets.finalize();
        let nets: Vec<Ipv4Net> = filtered_v4.iter().collect();

        assert_eq!(nets, vec![Ipv4Net::from_str("10.0.0.0/23").unwrap()]);
    }
}