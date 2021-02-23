use crate::{
    config::{config_folder_path, Config, ConfigError, Manager},
    utils::keys::{read_bitcoin_keys_file, read_noise_keys_file},
};
use revault_net::noise::SecretKey;
use revault_tx::bitcoin::{
    util::bip32::{ExtendedPrivKey, ExtendedPubKey},
    Network,
};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug)]
pub struct CosignerKeys {
    xpub: Option<ExtendedPubKey>,
    xpriv: Option<ExtendedPrivKey>,
    noise_priv: Option<SecretKey>,
}

impl CosignerKeys {
    fn new() -> Self {
        CosignerKeys {
            xpub: None,
            xpriv: None,
            noise_priv: None,
        }
    }

    fn set_bitcoin_keys(&mut self, bitcoin_keys_file: PathBuf) {
        let keys = read_bitcoin_keys_file(bitcoin_keys_file).expect("Reading bitcoin keys file");
        self.xpriv = Some(keys.0);
        self.xpub = Some(keys.1);
    }

    fn set_noise_key(&mut self, noise_keys_file: PathBuf) {
        self.noise_priv = Some(
            read_noise_keys_file(noise_keys_file)
                .expect("Reading noise keys file")
                .0,
        );
    }
}

/// Our global state
pub struct CosignerD {
    /// My keys
    pub cosigner_keys: CosignerKeys,
    /// The managers' xpubs
    pub managers: Vec<Manager>,
    /// ip::port (FIXME: default? always same?)
    pub addr: SocketAddr,
    // We store all our data in one place, that's here.
    pub data_dir: PathBuf,
    /// Bitcoin network
    pub network: Network,
}

pub fn create_datadir(datadir_path: &PathBuf) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    return {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = DirBuilder::new();
        builder.mode(0o700).recursive(true).create(datadir_path)
    };

    #[cfg(not(unix))]
    return {
        // FIXME: make Windows secure (again?)
        fs::create_dir_all(datadir_path)
    };
}

impl CosignerD {
    pub fn from_config(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let managers = config.managers;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);

        let mut data_dir = config.data_dir.unwrap_or(config_folder_path()?);

        data_dir.push(config.network.to_string());
        if !data_dir.as_path().exists() {
            if let Err(e) = create_datadir(&data_dir) {
                return Err(Box::from(ConfigError(format!(
                    "Could not create data dir '{:?}': {}.",
                    data_dir,
                    e.to_string()
                ))));
            }
        }
        data_dir = fs::canonicalize(data_dir)?;

        let cosigner_keys = CosignerKeys::new();

        let network = config.network;

        let mut cosignerd = CosignerD {
            cosigner_keys,
            managers,
            addr,
            data_dir,
            network,
        };

        cosignerd
            .cosigner_keys
            .set_bitcoin_keys(cosignerd.bitcoin_keys_file());
        cosignerd
            .cosigner_keys
            .set_noise_key(cosignerd.noise_keys_file());
        Ok(cosignerd)
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

    pub fn bitcoin_keys_file(&self) -> PathBuf {
        self.file_from_datadir("cosigner_bitcoin.keys")
    }

    pub fn noise_keys_file(&self) -> PathBuf {
        self.file_from_datadir("cosigner_noise.keys")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, utils::test_builder::CosignerTestBuilder};
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_cosignerd_from_config() {
        let test_framework = CosignerTestBuilder::new(3, 4).initialize().configure();
        let config =
            Config::from_file(Some(test_framework.get_config_path())).expect("Constructing Config");
        let _cosignerd = CosignerD::from_config(config).expect("Constructing cosignerd state");
    }
}
