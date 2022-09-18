# RevocationList2020

This library provides the implementation for the `RevocationList2020` proposal described [here](https://w3c-ccg.github.io/vc-status-rl-2020/#bib-rfc4648).



## Demo

The following demo uses the wasm library on a web page.

[![Demo](https://img.youtube.com/vi/XVyVVuNdWsE/0.jpg)](https://www.youtube.com/watch?v=XVyVVuNdWsE)


To run the demo locally, build the javascript library using:

```sh
wasm-pack build --target web --debug
```

and then launch a local web server, for example using python:

```sh
python3 -m http.server 7654
```


## Usage/Examples

The following example shows how to use the library with Rust.

https://github.com/noandrea/rl2020.rs/blob/aa3b2f099c6faa9f2ad45618cc3b0d4ae6bc0f4e/examples/main.rs#L5-L33

To run the example locally use the command:

```sh
cargo run --example main
```


## Running Tests

To run tests, run the following command

```bash
  cargo test
```

## Installation

### Rust

The rust library is published on [crates.io](https://crates.io/crates/rl2020)

### Npm

The wasm library is published on [npmjs](https://www.npmjs.com/package/rl2020)
