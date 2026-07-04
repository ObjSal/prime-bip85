//! Official BIP-85 test vectors, copied byte-for-byte from
//! bitcoin/bips bip-0085.mediawiki.

use bip85_core::bip85::{derive, derive_entropy, Application};
use bip85_core::{Network, Xprv};

const MASTER: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

fn root() -> Xprv {
    Xprv::parse(MASTER).expect("spec master xprv parses")
}

#[test]
fn master_xprv_round_trips() {
    assert_eq!(root().to_string(), MASTER);
}

#[test]
fn case_1_raw_entropy() {
    let entropy = derive_entropy(&root(), &[0, 0]).unwrap();
    assert_eq!(
        hex::encode(entropy),
        "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0\
         0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    );
}

#[test]
fn case_2_raw_entropy() {
    let entropy = derive_entropy(&root(), &[0, 1]).unwrap();
    assert_eq!(
        hex::encode(entropy),
        "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872\
         218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
    );
}

#[test]
fn bip39_12_words() {
    let d = derive(&root(), Application::Bip39 { words: 12 }, 0, Network::Mainnet).unwrap();
    assert_eq!(hex::encode(&d.entropy), "6250b68daf746d12a24d58b4787a714b");
    assert_eq!(
        d.display,
        "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    );
    assert_eq!(d.path, "m/83696968'/39'/0'/12'/0'");
}

#[test]
fn bip39_18_words() {
    let d = derive(&root(), Application::Bip39 { words: 18 }, 0, Network::Mainnet).unwrap();
    assert_eq!(hex::encode(&d.entropy), "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc");
    assert_eq!(
        d.display,
        "near account window bike charge season chef number sketch tomorrow \
         excuse sniff circle vital hockey outdoor supply token"
    );
}

#[test]
fn bip39_24_words() {
    let d = derive(&root(), Application::Bip39 { words: 24 }, 0, Network::Mainnet).unwrap();
    assert_eq!(
        hex::encode(&d.entropy),
        "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f"
    );
    assert_eq!(
        d.display,
        "puppy ocean match cereal symbol another shed magic wrap hammer bulb \
         intact gadget divorce twin tonight reason outdoor destroy simple truth \
         cigar social volcano"
    );
}

#[test]
fn hd_seed_wif() {
    let d = derive(&root(), Application::Wif, 0, Network::Mainnet).unwrap();
    assert_eq!(
        hex::encode(&d.entropy),
        "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"
    );
    assert_eq!(d.display, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp");
    assert_eq!(d.path, "m/83696968'/2'/0'");
}

#[test]
fn xprv_application() {
    let d = derive(&root(), Application::Xprv, 0, Network::Mainnet).unwrap();
    assert_eq!(
        hex::encode(&d.entropy[32..]),
        "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682"
    );
    assert_eq!(
        d.display,
        "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
    );
}

#[test]
fn hex_application() {
    let d = derive(&root(), Application::Hex { num_bytes: 64 }, 0, Network::Mainnet).unwrap();
    assert_eq!(
        d.display,
        "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785\
         55d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
    );
    assert_eq!(d.path, "m/83696968'/128169'/64'/0'");
}

/// Testnet re-encodings of the spec vectors. BIP-85 has no testnet vectors
/// (derivation is network-agnostic); these expected strings were computed
/// with an independent Python base58check implementation from the same
/// spec-pinned payloads (0xEF WIF prefix, 0x04358394 tprv version).
#[test]
fn testnet_wif() {
    let d = derive(&root(), Application::Wif, 0, Network::Testnet).unwrap();
    assert_eq!(
        hex::encode(&d.entropy),
        "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"
    );
    assert_eq!(d.display, "cRLuXpEtagka2NVmVtg6pcSdUFHp9pqkhCQSweYhQUWMwkdaaVsk");
}

#[test]
fn testnet_tprv() {
    let d = derive(&root(), Application::Xprv, 0, Network::Testnet).unwrap();
    assert_eq!(
        d.display,
        "tprv8ZgxMBicQKsPdh5yFmJBEQgjf3oaE8YyyEgS7CnEHXyPe9eGtubocMTq2BdvXjP6E9smCHogUm5ywmbfWPPhpVS3tM2MZbTaCPoTB1Yq51L"
    );
}

/// Every output except WIF/XPRV must be identical on every network — the
/// UI's network toggle only renders for those two, so this pins that the
/// others genuinely have no network dimension.
#[test]
fn network_only_affects_wif_and_xprv() {
    for app in [
        Application::Bip39 { words: 12 },
        Application::Bip39 { words: 24 },
        Application::Hex { num_bytes: 32 },
    ] {
        let m = derive(&root(), app, 0, Network::Mainnet).unwrap();
        let t = derive(&root(), app, 0, Network::Testnet).unwrap();
        assert_eq!(m.display, t.display, "{app:?} must be network-invariant");
        assert_eq!(m.entropy, t.entropy);
    }
    for app in [Application::Wif, Application::Xprv] {
        let m = derive(&root(), app, 0, Network::Mainnet).unwrap();
        let t = derive(&root(), app, 0, Network::Testnet).unwrap();
        assert_ne!(m.display, t.display, "{app:?} must be network-encoded");
        assert_eq!(m.entropy, t.entropy, "same child key, different serialization");
    }
}

/// Fingerprint math pinned by BIP-32's own test vector 1: seed
/// 000102030405060708090a0b0c0d0e0f → master identifier starts 3442193e.
#[test]
fn bip32_fingerprint_vector() {
    let seed: Vec<u8> = (0..16).collect();
    let root = Xprv::from_seed(&seed).unwrap();
    assert_eq!(root.fingerprint_hex().unwrap(), "3442193e");
}

/// A BIP-39 child's fingerprint must equal the fingerprint a wallet computes
/// after restoring from the displayed words; the XPRV child's must equal the
/// fingerprint of the string it displays.
#[test]
fn child_fingerprints_are_self_consistent() {
    let d = derive(&root(), Application::Bip39 { words: 12 }, 0, Network::Mainnet).unwrap();
    let restored = Xprv::from_bip39_entropy(&d.entropy, "").unwrap();
    assert_eq!(d.fingerprint.as_deref(), Some(restored.fingerprint_hex().unwrap().as_str()));

    let x = derive(&root(), Application::Xprv, 0, Network::Mainnet).unwrap();
    let parsed = Xprv::parse(&x.display).unwrap();
    assert_eq!(x.fingerprint.as_deref(), Some(parsed.fingerprint_hex().unwrap().as_str()));

    assert!(derive(&root(), Application::Wif, 0, Network::Mainnet).unwrap().fingerprint.is_none());
    assert!(derive(&root(), Application::Hex { num_bytes: 32 }, 0, Network::Mainnet)
        .unwrap()
        .fingerprint
        .is_none());
}

/// The device path: BIP-39 entropy in, root out. Uses the classic BIP-39
/// "TREZOR" test vector (all-zero 16-byte entropy → "abandon ... about") to
/// pin mnemonic_to_seed + from_seed end to end.
#[test]
fn root_from_bip39_entropy() {
    let root = Xprv::from_bip39_entropy(&[0u8; 16], "TREZOR").unwrap();
    // Expected values from the canonical BIP-39 vector list (trezor/python-mnemonic).
    let mnemonic = bip85_core::bip39::entropy_to_mnemonic(&[0u8; 16]).unwrap();
    assert_eq!(
        mnemonic,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    let seed = bip85_core::bip39::mnemonic_to_seed(&mnemonic, "TREZOR");
    assert_eq!(
        hex::encode(seed),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
         1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
    assert_eq!(root.depth, 0);
}

#[test]
fn seedqr_digits_for_derived_mnemonic() {
    // "girl mad pet ..." — girl=786, mad=1069, pet=1307 in the English list.
    let d = derive(&root(), Application::Bip39 { words: 12 }, 0, Network::Mainnet).unwrap();
    let digits = bip85_core::seedqr::seedqr_digits(&d.entropy).unwrap();
    assert_eq!(digits.len(), 48);
    assert!(digits.starts_with("078610691307"));
}
