use bgpkit_parser::{BgpkitParser, models::ElemType};
use clap::Parser;
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

    for elem in parser.into_elem_iter() {
        if !matches!(elem.elem_type, ElemType::ANNOUNCE) {
            continue;
        }

        let origins = match &elem.origin_asns {
            Some(origins) => origins,
            None => continue,
        };

        if origins.iter().any(|asn| asn_list.contains(&asn.to_u32())) {
            println!("{}", elem.prefix);
        }
    }
}
