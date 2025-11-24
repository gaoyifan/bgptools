use bgpkit_parser::{models::ElemType, BgpkitParser};
use std::collections::HashSet;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "bgptools")]
struct Opts {
    #[structopt(short, long, parse(from_os_str), default_value = "./rib")]
    mrt_file: PathBuf,

    #[structopt(required = true, min_values = 1)]
    asns: Vec<String>,
}

fn main() {
    let opts: Opts = Opts::from_args();
    let asn_list: HashSet<u32> = opts
        .asns
        .into_iter()
        .map(|x| x.parse::<u32>().expect("args(ASN) must be a number!"))
        .collect();

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

        if origins
            .iter()
            .any(|asn| asn_list.contains(&asn.to_u32()))
        {
            println!("{}", elem.prefix);
        }
    }
}
