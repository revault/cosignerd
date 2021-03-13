use revault_net::{noise::SecretKey as NoisePrivKey, sodiumoxide};
use revault_tx::bitcoin::secp256k1::{Error as SecpError, SecretKey as BitcoinPrivKey};

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

/// An error occuring during the handling of our keys
#[derive(Debug)]
pub enum KeyError {
    Noise(io::Error),
    BitcoinRead(io::Error),
    // All 0-2^256 numbers are valid private keys on Curve25519 (for Noise above), but that does
    // not hold for Bitcoin's secp256k1.
    /// Returned if the file does not contain a valid Secp256k1 private key
    BitcoinVerify(SecpError),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Noise(e) => write!(f, "Noise key initialization error: '{}'", e),
            Self::BitcoinRead(e) => write!(f, "Bitcoin key read error: '{}'", e),
            Self::BitcoinVerify(e) => write!(f, "Bitcoin key verification error: '{}'", e),
        }
    }
}

impl std::error::Error for KeyError {}

// The communication keys are (for now) hot, so we just create it ourselves on first run.
pub fn read_or_create_noise_key(secret_file: &PathBuf) -> Result<NoisePrivKey, KeyError> {
    let mut noise_secret = NoisePrivKey([0; 32]);

    if !secret_file.as_path().exists() {
        log::info!(
            "No Noise private key at '{:?}', generating a new one",
            secret_file
        );
        noise_secret = sodiumoxide::crypto::box_::gen_keypair().1;

        // We create it in read-only but open it in write only.
        let mut options = fs::OpenOptions::new();
        options = options.write(true).create_new(true).mode(0o400).clone();

        let mut fd = options.open(secret_file).map_err(KeyError::Noise)?;
        fd.write_all(&noise_secret.as_ref())
            .map_err(KeyError::Noise)?;
    } else {
        let mut noise_secret_fd = fs::File::open(secret_file).map_err(KeyError::Noise)?;
        noise_secret_fd
            .read_exact(&mut noise_secret.0)
            .map_err(KeyError::Noise)?;
    }

    // TODO: have a decent memory management and mlock() the key

    assert!(noise_secret.0 != [0; 32]);
    Ok(noise_secret)
}

// The Bitcoin key is hot too (for now) but is part of the onchain Script and is generated
// during the setup Ceremony.
pub fn read_bitcoin_privkey(secret_file: &PathBuf) -> Result<BitcoinPrivKey, KeyError> {
    // 0xffffff....ffff is not a valid privkey so this ensures we read correctly.
    let mut buf = [0xff; 32];

    let mut bitcoin_secret_fd = fs::File::open(secret_file).map_err(KeyError::BitcoinRead)?;
    bitcoin_secret_fd
        .read_exact(&mut buf)
        .map_err(KeyError::BitcoinRead)?;

    // FIXME: buf zeroization, mlock of the key, decent mem management
    BitcoinPrivKey::from_slice(&buf).map_err(KeyError::BitcoinVerify)
}
