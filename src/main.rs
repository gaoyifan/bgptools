use std::fs::File;

extern crate structopt;

use structopt::StructOpt;
use std::path::PathBuf;
use std::collections::HashSet;

extern crate mrt;

#[derive(StructOpt, Debug)]
#[structopt(name = "bgptools")]
struct Opts {
    #[structopt(short, long, parse(from_os_str), default_value = "./rib")]
    bgpdump_result: PathBuf,

    #[structopt(required = true, min_values = 1)]
    asns: Vec<String>,
}

fn main() {
    let opts: Opts = Opts::from_args();
    let asn_list: HashSet<u32> = opts.asns.into_iter()
        .map(|x| x.parse::<u32>().expect("args(ASN) must be a number!"))
        .collect();
    let file = File::open(&opts.bgpdump_result).unwrap();
    let entries = mrt::read_file_complete(file).unwrap();
    for entry in &entries {
        if entry.mrt_header.mrt_type != mrt::MrtType::TABLE_DUMP_V2 {
            continue
        }
        match &entry.message {
            mrt::MrtMessage::RIB_IPV4_UNICAST { header, entries } | mrt::MrtMessage::RIB_IPV6_UNICAST {header,entries} => {
                let cidr = format!("{}/{}", header.prefix, header.prefix_length);
                for e in entries {
                    for a in &e.bgp_attributes {
                        match &a.value {
                            mrt::BgpAttributeValue::AS_PATH { segments } => {
                                for s in segments {
                                    match s.segment_type {
                                        mrt::SegmentType::AS_SEQUENCE => {
                                            let asn = s.asns.last().unwrap_or(&0);
                                            if *asn > 0 && asn_list.contains(asn) {
                                                println!("{}",cidr);
                                            }
                                        },
                                        _ => {}
                                    }

                                }
                            },
                            _  => {}
                        }
                    }
                }
            },
            _ => {}
        }
    }
}
