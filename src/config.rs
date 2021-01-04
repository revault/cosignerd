//! This file contains functions needed to deserialize the configuration
//! file. The configuration file contains the static public keys for communication
//! with wallet clients (to set-up noise_KX channels) and bitcoin extended public
//! keys for each manager (for signature verification of Spend Transactions).

// TODO: Include parameters for Tor hidden service, and ip::port to listen for
// incoming messages on.

use revault_net::noise::{NoisePrivKey, NoisePubKey, KEY_SIZE};
use revault_tx::{bitcoin::Network, miniscript::descriptor::DescriptorPublicKey};
use serde::{de, Deserialize, Deserializer};
use std::{collections::HashMap, path::PathBuf, str::FromStr, vec::Vec};

/// A manager type that the cosigner will communicate with
#[derive(Debug)]
pub struct Manager {
    /// Bitcoin wallet public key
    pub xpub: DescriptorPublicKey,
    // Static noise public key
    pub noise_pubkey: NoisePubKey,
}

impl<'de> Deserialize<'de> for Manager {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = HashMap::<String, String>::deserialize(deserializer)?;

        let xpub_str = map
            .get("xpub")
            .ok_or_else(|| de::Error::custom(r#"No "xpub" for manager entry."#))?;

        let mut xpub = DescriptorPublicKey::from_str(&xpub_str).map_err(de::Error::custom)?;

        xpub = if let DescriptorPublicKey::XPub(mut xpub) = xpub {
            // We always derive from it, but from_str is a bit strict..
            xpub.is_wildcard = true;
            DescriptorPublicKey::XPub(xpub)
        } else {
            return Err(de::Error::custom("Need an xpub, not a raw public key."));
        };

        let noise_pubkey_array: [u8; KEY_SIZE] = serde_json::from_str(
            map.get("noise_pubkey")
                .ok_or_else(|| de::Error::custom(r#"No "noise_pubkey" for manager entry."#))?,
        )
        .map_err(|e| de::Error::custom(format!("Invalid \"noise_pubkey\" entry: {:?}", e)))?;
        let noise_pubkey = NoisePubKey(noise_pubkey_array);

        Ok(Manager { xpub, noise_pubkey })
    }
}

/// Static information required by cosigner to operate
#[derive(Debug, Deserialize)]
pub struct Config {
    /// The managers' xpubs
    pub managers: Vec<Manager>,
    /// Bitcoin network
    pub network: Network,
    /// An optional custom data directory
    pub data_dir: Option<PathBuf>,
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

/// Get the absolute path to the revault configuration folder.

/// It's a "revault/<network>/" directory in the XDG standard configuration directory for
/// all OSes but Linux-based ones, for which it's `~/.revault/<network>/`.
/// There is only one config file at `revault/config.toml`, which specifies the network.
/// Rationale: we want to have the database in the same folder as the
/// configuration file but for Linux the XDG specifies a data directory (`~/.local/share/`)
/// different from the configuration one (`~/.config/`).
pub fn config_folder_path() -> Result<PathBuf, ConfigError> {
    #[cfg(target_os = "linux")]
    let configs_dir = dirs::home_dir();

    #[cfg(not(target_os = "linux"))]
    let configs_dir = dirs::config_dir();

    if let Some(mut path) = configs_dir {
        #[cfg(target_os = "linux")]
        path.push(".revault");

        #[cfg(not(target_os = "linux"))]
        path.push("Revault");

        return Ok(path);
    }

    Err(ConfigError(
        "Could not locate the configuration directory.".to_owned(),
    ))
}

pub fn config_file_path() -> Result<PathBuf, ConfigError> {
    config_folder_path().map(|mut path| {
        path.push("revault.toml");
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
            network = "bitcoin"
            [[managers]]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            noise_pubkey = "[137, 236, 117, 33, 86, 176, 65, 253, 92, 172, 20, 249, 131, 155, 77, 60, 61, 194, 181, 65, 226, 99, 223, 207, 255, 71, 40, 219, 139, 152, 164, 120]"
            [[managers]]
            xpub = "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
            noise_pubkey = "[137, 236, 117, 33, 86, 176, 65, 253, 92, 172, 20, 249, 131, 155, 77, 60, 61, 194, 181, 65, 226, 99, 223, 207, 255, 71, 40, 219, 139, 152, 164, 120]"
            [[managers]]
            xpub = "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA"
            noise_pubkey = "[137, 236, 117, 33, 86, 176, 65, 253, 92, 172, 20, 249, 131, 155, 77, 60, 61, 194, 181, 65, 226, 99, 223, 207, 255, 71, 40, 219, 139, 152, 164, 120]"
        "#;
        let _config: Config = toml::from_str(toml_str).expect("Deserializing toml_str");
        println!("_config.data_dir: {:?}", _config.data_dir);

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

        #[cfg(target_os = "linux")]
        {
            assert!(filepath.as_path().starts_with("/home/"));
            assert!(filepath.as_path().ends_with(".revault/revault.toml"));
        }

        #[cfg(target_os = "macos")]
        assert!(filepath
            .as_path()
            .ends_with("Library/Application Support/Revault/revault.toml"));

        #[cfg(target_os = "windows")]
        assert!(filepath
            .as_path()
            .ends_with(r#"AppData\Roaming\Revault\revault.toml"#));
    }
}
