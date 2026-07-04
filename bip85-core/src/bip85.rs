//! BIP-85 applications over a BIP32 root key.
//!
//! Path layout: `m/83696968'/{app}'/{params...}'/{index}'`, all hardened.
//! Final entropy is `HMAC-SHA512(key="bip-entropy-from-k", msg=child_key)`.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bip32::{valid_scalar, Xprv};
use crate::{Error, Network};

pub const PURPOSE: u32 = 83696968; // "SEED" on a phone keypad

/// The BIP-85 applications this crate implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Application {
    /// 39': BIP-39 mnemonic, English, 12/18/24 words.
    Bip39 { words: u32 },
    /// 2': HD-Seed WIF (Bitcoin Core hdseed).
    Wif,
    /// 32': BIP32 root xprv.
    Xprv,
    /// 128169': raw hex entropy, 16–64 bytes.
    Hex { num_bytes: u32 },
}

/// A derived child secret: the display string plus the raw entropy behind it.
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedSecret {
    /// Human-facing result: mnemonic words, WIF, xprv string, or hex.
    pub display: String,
    /// The truncated derived entropy (mnemonic entropy, WIF key bytes, ...).
    pub entropy: Vec<u8>,
    /// Full derivation path, e.g. "m/83696968'/39'/0'/12'/0'".
    pub path: String,
    /// BIP-32 fingerprint of the child where one is defined: for BIP-39
    /// children, the fingerprint of the child mnemonic's own (no-passphrase)
    /// root — what a wallet restored from those words will display; for the
    /// XPRV application, the fingerprint of the encoded node. None for
    /// WIF/HEX, which aren't BIP-32 nodes.
    pub fingerprint: Option<String>,
}

/// Raw 64-byte BIP-85 entropy for an arbitrary sub-path (`path` WITHOUT the
/// leading purpose element; every element is hardened implicitly).
pub fn derive_entropy(root: &Xprv, path: &[u32]) -> Result<[u8; 64], Error> {
    let mut key = root.derive_hardened(PURPOSE)?;
    for &index in path {
        key = key.derive_hardened(index)?;
    }
    let mut mac = Hmac::<Sha512>::new_from_slice(b"bip-entropy-from-k")
        .expect("hmac accepts any key length");
    mac.update(&key.key);
    Ok(mac.finalize().into_bytes().into())
}

fn path_string(path: &[u32]) -> String {
    let mut s = format!("m/{PURPOSE}'");
    for p in path {
        s.push_str(&format!("/{p}'"));
    }
    s
}

/// `network` affects only the WIF/XPRV encodings; mnemonic and hex outputs
/// are identical on every network.
pub fn derive(
    root: &Xprv,
    app: Application,
    index: u32,
    network: Network,
) -> Result<DerivedSecret, Error> {
    let path: Vec<u32> = match app {
        Application::Bip39 { words } => {
            if !matches!(words, 12 | 18 | 24) {
                return Err(Error::BadParam);
            }
            vec![39, 0, words, index] // 0' = English
        }
        Application::Wif => vec![2, index],
        Application::Xprv => vec![32, index],
        Application::Hex { num_bytes } => {
            if !(16..=64).contains(&num_bytes) {
                return Err(Error::BadParam);
            }
            vec![128169, num_bytes, index]
        }
    };
    let mut full = derive_entropy(root, &path)?;
    let result = build(app, &full, &path, network);
    full.zeroize();
    result
}

fn build(
    app: Application,
    full: &[u8; 64],
    path: &[u32],
    network: Network,
) -> Result<DerivedSecret, Error> {
    let (display, entropy, fingerprint) = match app {
        Application::Bip39 { words } => {
            let bytes = words as usize * 4 / 3; // 12→16, 18→24, 24→32
            let entropy = full[..bytes].to_vec();
            let fp = Xprv::from_bip39_entropy(&entropy, "")?.fingerprint_hex()?;
            (crate::bip39::entropy_to_mnemonic(&entropy)?, entropy, Some(fp))
        }
        Application::Wif => {
            let key: [u8; 32] = full[..32].try_into().unwrap();
            valid_scalar(&key)?;
            // Compressed-pubkey WIF: version || key || 0x01.
            let mut raw = Vec::with_capacity(34);
            raw.push(match network {
                Network::Mainnet => 0x80,
                Network::Testnet => 0xEF,
            });
            raw.extend_from_slice(&key);
            raw.push(0x01);
            let wif = bs58::encode(&raw).with_check().into_string();
            raw.zeroize();
            (wif, key.to_vec(), None)
        }
        Application::Xprv => {
            // Left 256 bits chain code, right 256 bits private key; a root.
            let key: [u8; 32] = full[32..].try_into().unwrap();
            valid_scalar(&key)?;
            let xprv = Xprv {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: 0,
                chain_code: full[..32].try_into().unwrap(),
                key,
            };
            let fp = xprv.fingerprint_hex()?;
            (xprv.to_string_net(network), full.to_vec(), Some(fp))
        }
        Application::Hex { num_bytes } => {
            let entropy = full[..num_bytes as usize].to_vec();
            let hex: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
            (hex, entropy, None)
        }
    };
    Ok(DerivedSecret { display, entropy, path: path_string(path), fingerprint })
}
