# Rust DNS

<a href="https://travis-ci.org/oko/rust-dns"><img src="https://travis-ci.org/oko/rust-dns.svg?branch=master" alt="Travis CI Build Status" /></a>

A DNS library for the [Rust](http://rust-lang.org) language.

Sample client code is located in `src/bin/testclient.rs`. There is currently no write support, so it sends a captured sample packet doing a recursive `A`-record lookup for `facebook.com`, parses the response, and prints out an `fmt::Show` view of the response.

There are currently two implementations in the library.

## `dns::hp`
Minimal-allocation DNS packet parsing code. With ~500 byte packets (i.e., nameservers and glue records for the .com TLD), the rudimentary benchmark in `src/bin/benchmark.rs` it can handle about 160,000 packets per second with 4 threads on a quad-cord 2012 Retina MacBook Pro.

This implementation is very narrowly architected for fast parsing, and has no support for constructing packets.

## `dns::msg`
General-purpose DNS packet parsing and representation. Designed to support both parsing and construction of DNS queries and responses.
