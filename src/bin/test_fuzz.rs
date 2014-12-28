#![allow(dead_code,unused_imports,unused_must_use,unused_assignments)]
#![allow(deprecated)]
#![feature(slicing_syntax)]

//! Run fuzzing against the `dns::hp` parser.

extern crate dns;
extern crate time;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::{Ipv4Addr, SocketAddr};
use std::io::BufReader;
use std::io;
use std::rand::{Rng,StdRng,SeedableRng,random};
use std::sync::{Arc,Mutex};

//use dns::msg::{DNSMessageReader,Message};
//use dns::msg::record::{Question,ResourceRecord};
//use dns::number;

use dns::hp::read_dns_message;

fn main() {
    println!("===================");
    println!("Rust DNS Fuzz Tests");
    println!("===================\n");
    let mut buf = box [0u8, ..10000000u];
    // Use random seed for actual binary
    let mut rng: StdRng = StdRng::new().ok().unwrap();
    rand_buf(buf.as_mut_slice(), &mut rng);
    do_fuzz(buf.as_slice(), &mut rng, 1000000u);
    let pkt = include_bin!("../../tests/packets/net1-rs.bin");
    do_fuzz_rewrite(pkt, buf.as_mut_slice(), &mut rng, 1000000u);
}

#[test]
fn test_dns_hp_fuzzing() {
    let mut buf = [0u8, ..1000000u];
    // Use a fixed seed for integration tests
    let seed: &[_] = &[508, 53, 284, 224, 173, 23, 572, 634, 439, 983];
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    rand_buf(buf.as_mut_slice(), &mut rng);
    do_fuzz(buf.as_slice(), &mut rng, 10000u);
}

#[test]
fn test_dns_hp_fuzzing_rewrite() {
    let pkt = include_bin!("../../tests/packets/net1-rs.bin");
    let mut buf = [0u8, ..1000000u];
    // Use a fixed seed for integration tests
    let seed: &[_] = &[508, 53, 284, 224, 173, 23, 572, 634, 439, 983];
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    rand_buf(buf.as_mut_slice(), &mut rng);
    do_fuzz_rewrite(pkt, buf.as_mut_slice(), &mut rng, 10000u);
}

fn rand_buf(buf: &mut [u8], rng: &mut StdRng) {
    for i in range(0, buf.len()) {
        buf[i] = rng.gen::<u8>();
    }
}

fn rewrite(pkt: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(pkt.len());
    for i in range(0, pkt.len()) {
        v.push(pkt[i]);
    }
    v
}

fn do_fuzz_rewrite(pkt: &[u8], buf: &[u8], rng: &mut StdRng, iters: uint) {
    println!("Fuzz-RW: {} bytes of random data generated", buf.len()); io::stdio::flush();
    
    // Init counters
    let start = time::precise_time_ns();
    let mut oks = 0u;
    let mut errs = 0u;
    let mut tsz = 0u;
    let plen = pkt.len();


    for _ in range(0, iters) {
        let mut pkt2 = rewrite(pkt);
        // Generate start and end bounds
        let s = rng.gen::<uint>() % plen;
        let e = s+(rng.gen::<uint>() % (plen - s));

        for j in range(s, e) {
            pkt2[j] = random::<u8>();
        }

        // Test the current slice
        let (oki, eri) = fuzz(pkt2.as_slice());
        oks += oki;
        errs += eri;
        tsz += e-s;
    }

    // Calc results
    let end = time::precise_time_ns();
    let elapsed = (end - start) as f64 / 1000000000.;
    let avg_size = (tsz) as f64 / iters as f64;
    println!("Fuzz-RW: completed {} iterations in {}s ({} ok/{} err/rw {} byte avg)", iters, elapsed, oks, errs, avg_size);
}

fn do_fuzz(buf: &[u8], rng: &mut StdRng, iters: uint) {
    println!("Fuzz: {} bytes of random data generated", buf.len()); io::stdio::flush();
    
    // Init counters
    let start = time::precise_time_ns();
    let mut oks = 0u;
    let mut errs = 0u;
    let mut tsz = 0u;


    for i in range(0, iters) {
        // Generate start and end bounds
        let s = rng.gen::<uint>() % (buf.len() - 1025);
        let e = s+rng.gen::<uint>() % 1024;

        // Test the current slice
        let (oki, eri) = fuzz(buf[s..e]);
        i+1;
        tsz += e - s;
        oks += oki;
        errs += eri;
    }

    // Calc results
    let end = time::precise_time_ns();
    let elapsed = (end - start) as f64 / 1000000000.;
    let avg_size = (tsz) as f64 / iters as f64;
    println!("Fuzz: completed {} iterations in {}s ({} ok/{} err/{} byte avg)", iters, elapsed, oks, errs, avg_size);
}

fn fuzz(buf: &[u8]) -> (uint, uint) {
    let mut oks = 0u;
    let mut errs = 0u;
    let m = read_dns_message(buf);
    match m {
        Ok(_) => oks += 1,
        Err(_) => errs += 1,
    };
    (oks, errs)
}