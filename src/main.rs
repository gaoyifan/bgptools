use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;
use try_match::try_match;
use what_i_want::*;

extern crate mrt;

#[derive(StructOpt, Debug)]
#[structopt(name = "bgptools")]
struct Opts {
    #[structopt(short, long, parse(from_os_str), default_value = "./rib")]
    mrt_file: PathBuf,

    #[structopt(required = true, min_values = 1)]
    asns: Vec<String>,
}

macro_rules! match_or_continue {
    ($in:expr, $(|)? $($p:pat_param)|+ $(if $guard:expr)? => $out:expr) => {
        unwrap_or_continue!(try_match!($in, $($p)|+ $(if $guard)? => $out))
    };

    ($in:expr, $(|)? $($p:pat_param)|+ $(if $guard:expr)?) => {
        unwrap_or_continue!(try_match!($in, $($p)|+ $(if $guard)?))
    };
}

fn main() {
    let opts: Opts = Opts::from_args();
    let asn_list: HashSet<u32> = opts
        .asns
        .into_iter()
        .map(|x| x.parse::<u32>().expect("args(ASN) must be a number!"))
        .collect();
    let file = File::open(&opts.mrt_file).unwrap();
    let entries = mrt::read_file_complete(file).unwrap();
    for entry in &entries {
        match_or_continue!(&entry.mrt_header.mrt_type, mrt::MrtType::TABLE_DUMP_V2);
        let (header, entries) = match_or_continue!(
            &entry.message,
            mrt::MrtMessage::RIB_IPV4_UNICAST { header, entries }
                | mrt::MrtMessage::RIB_IPV6_UNICAST { header, entries } => (header, entries)
        );
        for e in entries {
            for a in &e.bgp_attributes {
                let segments = match_or_continue!(
                    &a.value,
                    mrt::BgpAttributeValue::AS_PATH { segments } => segments
                );
                for s in segments {
                    match_or_continue!(&s.segment_type, mrt::SegmentType::AS_SEQUENCE);
                    let asn = unwrap_or_continue!(s.asns.last());
                    if asn_list.contains(asn) {
                        println!("{}/{}", header.prefix, header.prefix_length);
                    }
                }
            }
        }
    }
}
