use crate::config::{datadir_path, Config, ConfigError, ManagerConfig};

use revault_net::{noise::SecretKey as NoisePrivKey, sodiumoxide};
use revault_tx::bitcoin::secp256k1::{
    key::ONE_KEY, Error as SecpError, SecretKey as BitcoinPrivKey,
};

use std::{
    fs,
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

/// An error occuring initializing our global state
#[derive(Debug)]
pub enum CosignerDError {
    NoiseKey(io::Error),
    BitcoinKeyRead(io::Error),
    // All 0-2^256 numbers are valid private keys on Curve25519 (for Noise above), but that does
    // not hold for Bitcoin's secp256k1.
    /// Returned if the file does not contain a valid Secp256k1 private key
    BitcoinKeyVerify(SecpError),
    ConfigError(ConfigError),
    DatadirCreation(io::Error),
}

impl std::fmt::Display for CosignerDError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoiseKey(e) => write!(f, "Noise key initialization error: '{}'", e),
            Self::BitcoinKeyRead(e) => write!(f, "Bitcoin key read error: '{}'", e),
            Self::BitcoinKeyVerify(e) => write!(f, "Bitcoin key verification error: '{}'", e),
            Self::ConfigError(e) => write!(f, "Configuration error: '{}'", e),
            Self::DatadirCreation(e) => write!(f, "Creating data directory: '{}'", e),
        }
    }
}

/// Our global state
#[derive(Debug)]
pub struct CosignerD {
    pub managers: Vec<ManagerConfig>,
    pub bitcoin_privkey: BitcoinPrivKey,
    pub noise_privkey: NoisePrivKey,

    pub listen: SocketAddr,
    // We store all our data in one place, that's here.
    pub data_dir: PathBuf,
}

// The communication keys are (for now) hot, so we just create it ourselves on first run.
fn read_or_create_noise_key(secret_file: &PathBuf) -> Result<NoisePrivKey, CosignerDError> {
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

        let mut fd = options
            .open(secret_file)
            .map_err(CosignerDError::NoiseKey)?;
        fd.write_all(&noise_secret.as_ref())
            .map_err(CosignerDError::NoiseKey)?;
    } else {
        let mut noise_secret_fd = fs::File::open(secret_file).map_err(CosignerDError::NoiseKey)?;
        noise_secret_fd
            .read_exact(&mut noise_secret.0)
            .map_err(CosignerDError::NoiseKey)?;
    }

    // TODO: have a decent memory management and mlock() the key

    assert!(noise_secret.0 != [0; 32]);
    Ok(noise_secret)
}

// The Bitcoin key is hot too (for now) but is part of the onchain Script and is generated
// during the setup Ceremony.
fn read_bitcoin_privkey(secret_file: &PathBuf) -> Result<BitcoinPrivKey, CosignerDError> {
    // 0xffffff....ffff is not a valid privkey so this ensures we read correctly.
    let mut buf = [0xff; 32];

    let mut bitcoin_secret_fd =
        fs::File::open(secret_file).map_err(CosignerDError::BitcoinKeyRead)?;
    bitcoin_secret_fd
        .read_exact(&mut buf)
        .map_err(CosignerDError::BitcoinKeyRead)?;

    // FIXME: buf zeroization, mlock of the key, decent mem management
    BitcoinPrivKey::from_slice(&buf).map_err(CosignerDError::BitcoinKeyVerify)
}

pub fn create_datadir(datadir_path: &PathBuf) -> Result<(), std::io::Error> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).recursive(true).create(datadir_path)
}

impl CosignerD {
    pub fn from_config(config: Config) -> Result<Self, CosignerDError> {
        let managers = config.managers;
        let listen = config.listen;

        let mut data_dir = config
            .data_dir
            .unwrap_or(datadir_path().map_err(CosignerDError::ConfigError)?);
        if !data_dir.as_path().exists() {
            create_datadir(&data_dir).map_err(CosignerDError::DatadirCreation)?;
        }
        data_dir = fs::canonicalize(data_dir).map_err(CosignerDError::DatadirCreation)?;

        let mut noise_key_path = data_dir.clone();
        noise_key_path.push("noise_secret");
        let noise_privkey = read_or_create_noise_key(&noise_key_path)?;

        let mut bitcoin_key_path = data_dir.clone();
        bitcoin_key_path.push("bitcoin_secret");
        let bitcoin_privkey = read_bitcoin_privkey(&bitcoin_key_path)?;

        Ok(CosignerD {
            managers,
            noise_privkey,
            bitcoin_privkey,
            listen,
            data_dir,
        })
    }

    fn file_from_datadir(&self, file_name: &str) -> PathBuf {
        let data_dir_str = self
            .data_dir
            .to_str()
            .expect("Impossible: the datadir path is valid unicode");

        [data_dir_str, file_name].iter().collect()
    }

    pub fn log_file(&self) -> PathBuf {
        self.file_from_datadir("log")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.file_from_datadir("cosignerd.pid")
    }

    pub fn db_file(&self) -> PathBuf {
        self.file_from_datadir("cosignerd.sqlite3")
    }
}
