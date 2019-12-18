use std::io::prelude::*;
use std::fs::File;
//use std::io::BufWriter;
use std::io::BufReader;

extern crate structopt;
use structopt::StructOpt;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(name = "bgptools")]
struct Opts {
    #[structopt(short, long, parse(from_os_str), default_value = "./rib.txt")]
    bgpdump_result: PathBuf,

    #[structopt(required = true, min_values = 1)]
    asns: Vec<String>,
}

fn main() {
    let opts: Opts = Opts::from_args();

    let asn_list: Vec<i32> = opts.asns.into_iter()
        .map(|x| x.parse::<i32>().expect("args(ASN) must be a number!"))
        .collect();
    let file = File::open(&opts.bgpdump_result).unwrap();
    let fin = BufReader::new(file);
    let get_cidr = |line_result: Result<String, std::io::Error>| {
        let line = line_result.unwrap();
        let elems: Vec<&str> = line.split('|').collect();
        let cidr = elems[5];
        let aggregator: &str = elems[13];
        let aspath: Vec<i32> = elems[6]
            .split(' ')
            .map(|x| match x.parse::<i32>() {
                Ok(asn) => asn,
                Err(_) => {
                    aggregator
                        .split(' ')
                        .next()
                        .unwrap()
                        .parse::<i32>()
                        .unwrap_or(0)
                }
            })
            .collect::<Vec<i32>>();
        let mut asn: i32 = 0;
        if aspath.len() > 0 {
            asn = aspath[aspath.len() - 1];
        }
        if asn > 0 && asn_list.iter().find(|&&x| x == asn).is_some() {
            println!("{}",cidr);
        }
    };
    fin.lines().for_each(get_cidr);
}
