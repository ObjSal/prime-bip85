//! Host-side BIP-85 derivation, for cross-checking what the device shows:
//!   cargo run -p bip85-core --example derive -- <entropy-hex> <app> <index> [testnet]
//! where <app> is words12|words24|wif|xprv|hex32.

use bip85_core::bip85::{derive, Application};
use bip85_core::{Network, Xprv};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (entropy_hex, app, index, network) = match args.as_slice() {
        [_, e, a, i] => (e.clone(), a.clone(), i.parse::<u32>().expect("index"), Network::Mainnet),
        [_, e, a, i, t] if t == "testnet" => {
            (e.clone(), a.clone(), i.parse::<u32>().expect("index"), Network::Testnet)
        }
        _ => {
            eprintln!("usage: derive <entropy-hex> <words12|words24|wif|xprv|hex32> <index> [testnet]");
            std::process::exit(2);
        }
    };
    let entropy: Vec<u8> = (0..entropy_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).expect("hex"))
        .collect();
    let app = match app.as_str() {
        "words12" => Application::Bip39 { words: 12 },
        "words24" => Application::Bip39 { words: 24 },
        "wif" => Application::Wif,
        "xprv" => Application::Xprv,
        "hex32" => Application::Hex { num_bytes: 32 },
        other => panic!("unknown app {other}"),
    };
    let root = Xprv::from_bip39_entropy(&entropy, "").expect("root");
    println!("master fp: {}", root.fingerprint_hex().expect("fingerprint"));
    let d = derive(&root, app, index, network).expect("derive");
    println!("path:    {}", d.path);
    println!("display: {}", d.display);
    if let Some(fp) = &d.fingerprint {
        println!("child fp: {fp}");
    }
}
