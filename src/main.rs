use std::io::prelude::*;
use std::fs::File;
//use std::io::BufWriter;
use std::io::BufReader;

fn main() {
    let asn_list: Vec<i32> = std::env::args()
        .skip(1)
        .map(|x| x.parse::<i32>().expect("args(ASN) must be a number!"))
        .collect();
    let file = File::open("./rib.txt").unwrap();
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
            Some(cidr.to_string())
        } else {
            None
        }
    };
    fin.lines().map(get_cidr).collect::<Vec<_>>();
}
