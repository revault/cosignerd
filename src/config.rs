//! This file contains functions needed to deserialize the configuration
//! file. The configuration file contains the static public keys for communication
//! with wallet clients (to set-up noise_KK channels) and bitcoin DescriptorPublicKeys
//! for each manager (for signature verification of Spend Transactions).

use revault_net::noise::PublicKey as NoisePubkey;
use revault_tx::bitcoin::hashes::hex::FromHex;

use std::{env, net::SocketAddr, path::PathBuf, process, str::FromStr, vec::Vec};

use serde::{de, Deserialize, Deserializer};

fn deserialize_noisepubkey<'de, D>(deserializer: D) -> Result<NoisePubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let data = String::deserialize(deserializer)?;
    FromHex::from_hex(&data)
        .map_err(|e| de::Error::custom(e))
        .map(NoisePubkey)
}

fn deserialize_loglevel<'de, D>(deserializer: D) -> Result<log::LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let level_str = String::deserialize(deserializer)?;
    log::LevelFilter::from_str(&level_str).map_err(de::Error::custom)
}

fn listen_default() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8383))
}

fn loglevel_default() -> log::LevelFilter {
    log::LevelFilter::Info
}

fn daemon_default() -> bool {
    false
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagerConfig {
    #[serde(deserialize_with = "deserialize_noisepubkey")]
    pub noise_key: NoisePubkey,
}

fn default_datadir_path() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|mut path| {
            path.push(".cosignerd");
            path
        })
        .unwrap_or_else(|| {
            eprintln!("Could not locate our default data directory, no $HOME set?");
            process::exit(1);
        })
}

/// Static informations we require to operate
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The managers', for which we need the Noise static pubkeys
    pub managers: Vec<ManagerConfig>,
    /// An optional custom data directory
    #[serde(default = "default_datadir_path")]
    pub data_dir: PathBuf,
    /// What interface to listen on
    #[serde(default = "listen_default")]
    pub listen: SocketAddr,
    /// Whether to daemonize the process
    #[serde(default = "daemon_default")]
    pub daemon: bool,
    /// What messages to log
    #[serde(
        deserialize_with = "deserialize_loglevel",
        default = "loglevel_default"
    )]
    pub log_level: log::LevelFilter,
}

#[derive(Debug)]
pub enum ConfigError {
    ReadingConfigFile(std::io::Error),
    ParsingConfigFile(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ReadingConfigFile(e) => write!(f, "Error when reading config file: '{}'", e),
            Self::ParsingConfigFile(e) => write!(f, "Error when reading config file: '{}'", e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Get the default path to our config file, inside the data directory
pub fn default_config_file_path() -> PathBuf {
    let mut path = default_datadir_path();
    path.push("config.toml");
    path
}

impl Config {
    /// Get our static configuration out of a mandatory configuration file.
    ///
    /// We require all settings to be set in the configuration file, and only in the configuration
    /// file. We don't allow to set them via the command line or environment variables to avoid a
    /// futile duplication.
    pub fn from_file(custom_path: Option<PathBuf>) -> Result<Config, ConfigError> {
        let config_file = custom_path.unwrap_or_else(|| default_config_file_path());

        let config = std::fs::read(&config_file)
            .map_err(ConfigError::ReadingConfigFile)
            .and_then(|file_content| {
                toml::from_slice::<Config>(&file_content).map_err(ConfigError::ParsingConfigFile)
            })?;

        Ok(config)
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

#[cfg(test)]
mod tests {
    use super::{default_config_file_path, Config};

    // Test the format of the configuration file
    #[test]
    fn deserialize_toml_config() {
        // A valid config
        let toml_str = r#"
            data_dir = "tests/"

            # Note that we don't need to provide 'listen', it'll just use the default.

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
        let filepath = default_config_file_path();

        assert!(filepath.as_path().starts_with("/home/"));
        assert!(filepath.as_path().ends_with(".cosignerd/config.toml"));
    }
}
