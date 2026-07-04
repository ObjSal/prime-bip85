//! BIP-85 deterministic entropy derivation (bitcoin/bips bip-0085.mediawiki).
//!
//! Everything here is pure computation over a BIP32 root key so the whole
//! crate runs (and is tested) on the host. The device app obtains the master
//! seed entropy via KeyOS `GetSeed`, turns it into a root with
//! [`Xprv::from_bip39_entropy`], and calls the application functions.

pub mod bip32;
pub mod bip39;
pub mod bip85;
pub mod seedqr;

pub use bip32::Xprv;
pub use bip85::{Application, DerivedSecret};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Base58/version/length problem parsing an xprv string.
    BadXprv,
    /// Entropy length is not one of the BIP-39 sizes (16/24/32 bytes).
    BadEntropyLen,
    /// Derived key material fell outside the secp256k1 group order
    /// (probability ~2^-127; the spec says to treat it as an error).
    InvalidKey,
    /// Unsupported parameter (word count, hex byte length, ...).
    BadParam,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::BadXprv => "invalid xprv",
            Error::BadEntropyLen => "entropy must be 16, 24 or 32 bytes",
            Error::InvalidKey => "derived key outside curve order",
            Error::BadParam => "unsupported parameter",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}
