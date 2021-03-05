use crate::config::{datadir_path, Config, ConfigError, ManagerConfig};
use std::{fs, net::SocketAddr, os::unix::fs::DirBuilderExt, path::PathBuf};

/// Our global state
#[derive(Debug)]
pub struct CosignerD {
    pub managers: Vec<ManagerConfig>,

    pub listen: SocketAddr,
    // We store all our data in one place, that's here.
    pub data_dir: PathBuf,
}

pub fn create_datadir(datadir_path: &PathBuf) -> Result<(), std::io::Error> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).recursive(true).create(datadir_path)
}

impl CosignerD {
    pub fn from_config(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let managers = config.managers;
        let listen = config.listen;

        let mut data_dir = config.data_dir.unwrap_or(datadir_path()?);
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

        Ok(CosignerD {
            managers,
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
