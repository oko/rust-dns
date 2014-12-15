# Rust DNS

<a href="https://travis-ci.org/oko/rust-dns"><img src="https://travis-ci.org/oko/rust-dns.svg?branch=master" alt="Travis CI Build Status" /></a>

A DNS library for the [Rust](http://rust-lang.org) language.

Sample client code is located in `src/bin/testclient.rs`. There is currently no write support, so it sends a captured sample packet doing a recursive `A`-record lookup for `facebook.com`, parses the response, and prints out an `fmt::Show` view of the response.
