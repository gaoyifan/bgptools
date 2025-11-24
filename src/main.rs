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

fn main() {
    let opts: Opts = Opts::parse();
    let asn_list: HashSet<u32> = opts.asns.into_iter().collect();

    let rib_path = opts.mrt_file.to_string_lossy().into_owned();
    let parser =
        BgpkitParser::new(rib_path.as_str()).expect("failed to open MRT/RIB file with bgpkit");

    let mut included_v4 = IpRange::<Ipv4Net>::new();
    let mut included_v6 = IpRange::<Ipv6Net>::new();
    let mut excluded_v4 = IpRange::<Ipv4Net>::new();
    let mut excluded_v6 = IpRange::<Ipv6Net>::new();

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

        let origin_numbers: Vec<u32> = origins.iter().map(|asn| asn.to_u32()).collect();

        record_prefix(
            &asn_list,
            &origin_numbers,
            net,
            &mut included_v4,
            &mut included_v6,
            &mut excluded_v4,
            &mut excluded_v6,
        );
    }

    let (filtered_v4, filtered_v6) =
        finalize_ranges(included_v4, included_v6, excluded_v4, excluded_v6);

    emit_sorted_ipv4(&filtered_v4);
    emit_sorted_ipv6(&filtered_v6);
}

fn record_prefix(
    asn_list: &HashSet<u32>,
    origins: &[u32],
    net: IpNet,
    included_v4: &mut IpRange<Ipv4Net>,
    included_v6: &mut IpRange<Ipv6Net>,
    excluded_v4: &mut IpRange<Ipv4Net>,
    excluded_v6: &mut IpRange<Ipv6Net>,
) {
    let has_included_origin = origins.iter().any(|asn| asn_list.contains(asn));

    match (net, has_included_origin) {
        (IpNet::V4(prefix), true) => {
            included_v4.add(prefix);
        }
        (IpNet::V6(prefix), true) => {
            included_v6.add(prefix);
        }
        (IpNet::V4(prefix), false) => {
            excluded_v4.add(prefix);
        }
        (IpNet::V6(prefix), false) => {
            excluded_v6.add(prefix);
        }
    }
}

fn finalize_ranges(
    included_v4: IpRange<Ipv4Net>,
    included_v6: IpRange<Ipv6Net>,
    excluded_v4: IpRange<Ipv4Net>,
    excluded_v6: IpRange<Ipv6Net>,
) -> (IpRange<Ipv4Net>, IpRange<Ipv6Net>) {
    let filtered_v4 = finalize_range(included_v4, excluded_v4);
    let filtered_v6 = finalize_range(included_v6, excluded_v6);
    (filtered_v4, filtered_v6)
}

fn finalize_range<N>(mut included: IpRange<N>, excluded: IpRange<N>) -> IpRange<N>
where
    N: IpRangeNet + ToNetwork<N> + Clone,
{
    included.simplify();
    let mut excluded = excluded;
    excluded.simplify();
    let mask = mask_more_specific(&included, &excluded);
    let mut filtered = included.exclude(&mask);
    filtered.simplify();
    filtered
}

fn mask_more_specific<N>(included: &IpRange<N>, excluded: &IpRange<N>) -> IpRange<N>
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
    mask
}

fn sorted_ipv4(range: &IpRange<Ipv4Net>) -> Vec<Ipv4Net> {
    let mut nets: Vec<Ipv4Net> = range.iter().collect();
    nets.sort_unstable_by(|a, b| match a.addr().cmp(&b.addr()) {
        std::cmp::Ordering::Equal => a.prefix_len().cmp(&b.prefix_len()),
        other => other,
    });
    nets
}

fn sorted_ipv6(range: &IpRange<Ipv6Net>) -> Vec<Ipv6Net> {
    let mut nets: Vec<Ipv6Net> = range.iter().collect();
    nets.sort_unstable_by(|a, b| match a.addr().cmp(&b.addr()) {
        std::cmp::Ordering::Equal => a.prefix_len().cmp(&b.prefix_len()),
        other => other,
    });
    nets
}

fn emit_sorted_ipv4(range: &IpRange<Ipv4Net>) {
    for net in sorted_ipv4(range) {
        println!("{}", net);
    }
}

fn emit_sorted_ipv6(range: &IpRange<Ipv6Net>) {
    for net in sorted_ipv6(range) {
        println!("{}", net);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case1_masks_more_specific_prefix() {
        let expected = vec![
            "10.0.0.0/9",
            "10.128.0.0/10",
            "10.192.0.0/11",
            "10.224.0.0/12",
            "10.240.0.0/13",
            "10.248.0.0/14",
            "10.252.0.0/15",
            "10.254.0.0/16",
        ];
        let output = run_case(&[1000], &["AS 1000  10.0.0.0/8", "AS 1001  10.255.0.0/16"]);
        assert_eq!(output, expected);
    }

    #[test]
    fn case2_same_length_prefix_not_masked() {
        let expected = vec!["10.0.0.0/8"];
        let output = run_case(&[1000], &["AS 1000  10.0.0.0/8", "AS 1001  10.0.0.0/8"]);
        assert_eq!(output, expected);
    }

    #[test]
    fn case3_shorter_prefix_not_masked() {
        let expected = vec!["10.0.0.0/8"];
        let output = run_case(&[1000], &["AS 1000  10.0.0.0/8", "AS 1001  10.0.0.0/7"]);
        assert_eq!(output, expected);
    }

    fn run_case(asn_list: &[u32], input: &[&str]) -> Vec<String> {
        let asn_list: HashSet<u32> = asn_list.iter().copied().collect();
        let mut included_v4 = IpRange::<Ipv4Net>::new();
        let mut included_v6 = IpRange::<Ipv6Net>::new();
        let mut excluded_v4 = IpRange::<Ipv4Net>::new();
        let mut excluded_v6 = IpRange::<Ipv6Net>::new();

        for line in input {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            assert!(parts.len() >= 3, "invalid input line: {trimmed}");
            let asn: u32 = parts[1].parse().expect("invalid ASN");
            let net: IpNet = parts[2].parse().expect("invalid prefix");
            let origins = vec![asn];
            record_prefix(
                &asn_list,
                &origins,
                net,
                &mut included_v4,
                &mut included_v6,
                &mut excluded_v4,
                &mut excluded_v6,
            );
        }

        let (filtered_v4, _filtered_v6) =
            finalize_ranges(included_v4, included_v6, excluded_v4, excluded_v6);

        sorted_ipv4(&filtered_v4)
            .into_iter()
            .map(|net| net.to_string())
            .collect()
    }
}
