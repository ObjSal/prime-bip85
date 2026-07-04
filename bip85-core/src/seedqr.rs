//! Standard SeedQR payload (SeedSigner spec): each word's wordlist index as
//! a 4-digit zero-padded decimal, concatenated. Encoded by the UI layer as a
//! digit-mode QR so any SeedQR-aware wallet can restore the mnemonic.

use crate::Error;

pub fn seedqr_digits(entropy: &[u8]) -> Result<String, Error> {
    let indices = crate::bip39::entropy_to_indices(entropy)?;
    Ok(indices.into_iter().map(|i| format!("{i:04}")).collect())
}
