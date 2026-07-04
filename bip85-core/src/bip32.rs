//! Minimal BIP32: root-from-seed, hardened-only CKDpriv, xprv parse/serialize.
//! Hardened-only derivation never needs a public key, so no EC point math —
//! just scalar addition mod n via k256.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Network};

const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // mainnet "xprv…"
const TPRV_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // testnet "tprv…"
pub const HARDENED: u32 = 0x8000_0000;

/// A private extended key. Only the fields BIP-85 needs; depth/fingerprint/
/// child-number are tracked so serialization of a *root* key is exact.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Xprv {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key: [u8; 32],
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

impl Xprv {
    /// BIP32 master key from a 64-byte seed (`HMAC-SHA512("Bitcoin seed", seed)`).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let (il, ir) = i.split_at(32);
        let key: [u8; 32] = il.try_into().unwrap();
        valid_scalar(&key)?;
        Ok(Xprv {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code: ir.try_into().unwrap(),
            key,
        })
    }

    /// Root key from BIP-39 entropy (16/24/32 bytes) + optional passphrase —
    /// the path the device app takes from KeyOS `GetSeed`.
    pub fn from_bip39_entropy(entropy: &[u8], passphrase: &str) -> Result<Self, Error> {
        let mnemonic = crate::bip39::entropy_to_mnemonic(entropy)?;
        let seed = crate::bip39::mnemonic_to_seed(&mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// Parse a base58check `xprv...` string.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let raw = bs58::decode(s).with_check(None).into_vec().map_err(|_| Error::BadXprv)?;
        if raw.len() != 78 || raw[0..4] != XPRV_VERSION || raw[45] != 0 {
            return Err(Error::BadXprv);
        }
        Ok(Xprv {
            depth: raw[4],
            parent_fingerprint: raw[5..9].try_into().unwrap(),
            child_number: u32::from_be_bytes(raw[9..13].try_into().unwrap()),
            chain_code: raw[13..45].try_into().unwrap(),
            key: raw[46..78].try_into().unwrap(),
        })
    }

    /// Serialize to the base58check `xprv...` (mainnet) form.
    pub fn to_string(&self) -> String {
        self.to_string_net(Network::Mainnet)
    }

    /// Serialize with the given network's version bytes (`xprv…`/`tprv…`).
    pub fn to_string_net(&self, network: Network) -> String {
        let version = match network {
            Network::Mainnet => XPRV_VERSION,
            Network::Testnet => TPRV_VERSION,
        };
        let mut raw = Vec::with_capacity(78);
        raw.extend_from_slice(&version);
        raw.push(self.depth);
        raw.extend_from_slice(&self.parent_fingerprint);
        raw.extend_from_slice(&self.child_number.to_be_bytes());
        raw.extend_from_slice(&self.chain_code);
        raw.push(0);
        raw.extend_from_slice(&self.key);
        bs58::encode(raw).with_check().into_string()
    }

    /// Hardened CKDpriv. `index` is the child number *without* the hardened
    /// bit; the parent fingerprint of the result is left zeroed because
    /// BIP-85 never serializes derived children.
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Error> {
        let child_number = index | HARDENED;
        let mut data = Vec::with_capacity(37);
        data.push(0);
        data.extend_from_slice(&self.key);
        data.extend_from_slice(&child_number.to_be_bytes());
        let i = hmac_sha512(&self.chain_code, &data);
        data.zeroize();
        let (il, ir) = i.split_at(32);

        let il_scalar = scalar(il.try_into().unwrap())?;
        let parent = scalar(&self.key)?;
        let child = il_scalar + parent;
        if child == Scalar::ZERO {
            return Err(Error::InvalidKey);
        }
        Ok(Xprv {
            depth: self.depth + 1,
            parent_fingerprint: [0; 4],
            child_number,
            chain_code: ir.try_into().unwrap(),
            key: child.to_repr().into(),
        })
    }
}

fn scalar(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    let ct = Scalar::from_repr((*bytes).into());
    Option::<Scalar>::from(ct).ok_or(Error::InvalidKey)
}

/// A key must be a valid non-zero scalar to be usable.
pub fn valid_scalar(bytes: &[u8; 32]) -> Result<(), Error> {
    let s = scalar(bytes)?;
    if s == Scalar::ZERO {
        return Err(Error::InvalidKey);
    }
    Ok(())
}
