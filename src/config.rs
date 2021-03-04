//! This file contains functions needed to deserialize the configuration
//! file. The configuration file contains the static public keys for communication
//! with wallet clients (to set-up noise_KK channels) and bitcoin DescriptorPublicKeys
//! for each manager (for signature verification of Spend Transactions).

use revault_net::noise::PublicKey as NoisePubkey;
use revault_tx::{
    bitcoin::{hashes::hex::FromHex, util::bip32, PublicKey as BitcoinPubkey},
    miniscript::descriptor::{DescriptorPublicKey, DescriptorSinglePub, DescriptorXKey},
};
use serde::{de, Deserialize, Deserializer};
use std::{path::PathBuf, vec::Vec};

pub fn deserialize_noisepubkey<'de, D>(deserializer: D) -> Result<NoisePubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let data = String::deserialize(deserializer)?;
    FromHex::from_hex(&data)
        .map_err(|e| de::Error::custom(e))
        .map(NoisePubkey)
}

fn xpub_to_desc_xpub(xkey: bip32::ExtendedPubKey) -> DescriptorPublicKey {
    DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey,
        derivation_path: bip32::DerivationPath::from(vec![]),
        is_wildcard: true,
    })
}

fn deserialize_xpub<'de, D>(deserializer: D) -> Result<DescriptorPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let xpub = bip32::ExtendedPubKey::deserialize(deserializer)?;
    Ok(xpub_to_desc_xpub(xpub))
}

fn deserialize_xpubs<'de, D>(deserializer: D) -> Result<Vec<DescriptorPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let xpubs = Vec::<bip32::ExtendedPubKey>::deserialize(deserializer)?;
    Ok(xpubs.into_iter().map(xpub_to_desc_xpub).collect())
}

fn deserialize_single_keys<'de, D>(deserializer: D) -> Result<Vec<DescriptorPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let xpubs = Vec::<BitcoinPubkey>::deserialize(deserializer)?;
    Ok(xpubs
        .into_iter()
        .map(|key| DescriptorPublicKey::SinglePub(DescriptorSinglePub { origin: None, key }))
        .collect())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagerConfig {
    #[serde(deserialize_with = "deserialize_xpub")]
    pub xpub: DescriptorPublicKey,
    #[serde(deserialize_with = "deserialize_noisepubkey")]
    pub noise_key: NoisePubkey,
}

/// Static informations we require to operate
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The stakeholders' xpubs, which we need to reconstruct the transactions
    #[serde(deserialize_with = "deserialize_xpubs")]
    pub stakeholders_xpubs: Vec<DescriptorPublicKey>,
    /// The cosigners' static public keys, includes our own
    #[serde(deserialize_with = "deserialize_single_keys")]
    pub cosigners_keys: Vec<DescriptorPublicKey>,
    /// The managers', which we need the xpubs and Noise static pubkeys
    pub managers: Vec<ManagerConfig>,
    /// The unvault output scripts relative timelock
    pub unvault_csv: u32,
    /// An optional custom data directory
    pub data_dir: Option<PathBuf>,
    /// Whether to daemonize the process
    pub daemon: Option<bool>,
    /// What messages to log
    pub log_level: Option<String>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Get the absolute path to the our configuration folder, it's `~/.cosignerd`.
pub fn datadir_path() -> Result<PathBuf, ConfigError> {
    dirs::home_dir()
        .map(|mut path| {
            path.push(".cosignerd");
            path
        })
        .ok_or_else(|| ConfigError("Could not locate our data directory.".to_owned()))
}

/// Get the path to our config file, inside the data directory
pub fn config_file_path() -> Result<PathBuf, ConfigError> {
    datadir_path().map(|mut path| {
        path.push("config.toml");
        path
    })
}

impl Config {
    /// Get our static configuration out of a mandatory configuration file.
    ///
    /// We require all settings to be set in the configuration file, and only in the configuration
    /// file. We don't allow to set them via the command line or environment variables to avoid a
    /// futile duplication.
    pub fn from_file(custom_path: Option<PathBuf>) -> Result<Config, ConfigError> {
        let config_file = custom_path.unwrap_or(config_file_path()?);

        let config = std::fs::read(&config_file)
            .map_err(|e| ConfigError(format!("Reading configuration file: {}", e)))
            .and_then(|file_content| {
                toml::from_slice::<Config>(&file_content)
                    .map_err(|e| ConfigError(format!("Parsing configuration file: {}", e)))
            })?;

        if config.stakeholders_xpubs.len() != config.cosigners_keys.len() {
            return Err(ConfigError(
                "Number of stakeholders xpubs and cosigning servers keys mismatch".to_string(),
            ));
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{config_file_path, Config};

    // Test the format of the configuration file
    #[test]
    fn deserialize_toml_config() {
        // A valid config
        let toml_str = r#"
            data_dir = "tests/"

            stakeholders_xpubs = [
                "xpub661MyMwAqRbcEfj3aPs1HJtoyXfVqnqzrDCahd6Uvv7qMYc8AyG33UMNzGybwTBwKH5VZJMHaP4AWebzBtPbjvTPVEJjp2rEtaHZn6cgspv",
                "xpub661MyMwAqRbcEaNLwKNmwFBcTyjVrjvv2Ce63kHaXFDtGXwyzzQEQQy4X3nAGTtCVYPpU9mntFmvowhfF1fAwqjRXamfdX4U2V8RGVrY6oD"
            ]
            cosigners_keys = [
                "035ce843b5a153689c40946857502e04f45fe8e01993bb0b8d4035ec0f56c3a30a",
                "02ab2e8fdb07d82a911a899f49a0f73d5585e248ed2a2d67bb0c776a609da3edd9"
            ]

            unvault_csv = 42

            [[managers]]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            noise_key = "91526407c80aa457ce89e8faef1bef2e7c7e303ae2f578e5e4f33465cbb9d0a9"
            [[managers]]
            xpub = "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
            noise_key = "72c9be5363932b1aeaf1d8fa4bf0047b4e03c6e7e2f8db4c64876dc176b986cf"
            [[managers]]
            xpub = "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA"
            noise_key = "653bf272f7b691a0fa58fd9736693fbc09f18fc8648a66be6341ef7f3b1254f7"
        "#;
        let _config: Config = toml::from_str(toml_str).expect("Deserializing toml_str");

        // Missing field "managers", will result in error
        let toml_str = r#"
            [cosigner_keys]
            pubkey = "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2" 
        "#;
        let config_res: Result<Config, toml::de::Error> = toml::from_str(toml_str);
        config_res.expect_err("Deserializing an invalid toml_str");
    }

    #[test]
    fn config_directory() {
        let filepath = config_file_path().expect("Getting config file path");

        assert!(filepath.as_path().starts_with("/home/"));
        assert!(filepath.as_path().ends_with(".cosignerd/config.toml"));
    }
}
