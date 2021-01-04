use crate::{
    cosignerd::CosignerD,
    database::{interface::*, schema::SCHEMA, DatabaseError, DB_VERSION},
};
use revault_tx::miniscript::bitcoin::{OutPoint, Txid};
use rusqlite::params;
use std::{fs, path::PathBuf};

// Sqlite supports up to i64, thus rusqlite prevents us from inserting u64's.
// We use this to panic rather than inserting a truncated integer into the database (as we'd have
// done by using `n as u32`).
// fn timestamp_to_u32(n: u64) -> u32 {
//     n.try_into()
//         .expect("Is this the year 2106 yet? Misconfigured system clock.")
// }

// Create the db file with RW permissions only for the user
fn create_db_file(db_path: &PathBuf) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    let options = options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    return {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600).open(db_path)?;
        Ok(())
    };

    #[cfg(not(unix))]
    return {
        // FIXME: make Windows secure (again?)
        options.open(db_path)?;
        Ok(())
    };
}

pub fn create_db(cosignerd: &CosignerD) -> Result<(), DatabaseError> {
    let db_path = cosignerd.db_file();

    // Rusqlite could create it for us, but we want custom permissions
    create_db_file(&db_path)
        .map_err(|e| DatabaseError(format!("Creating db file: {}", e.to_string())))?;

    db_exec(&db_path, |tx| {
        tx.execute_batch(&SCHEMA)
            .map_err(|e| DatabaseError(format!("Creating database: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO db_params (version, network) VALUES (?1, ?2)",
            params![DB_VERSION, cosignerd.network.to_string()],
        )
        .map_err(|e| DatabaseError(format!("Inserting db_params: {}", e.to_string())))?;
        Ok(())
    })
}

// Called on startup to check database integrity
fn check_db(cosignerd: &CosignerD) -> Result<(), DatabaseError> {
    let db_path = cosignerd.db_file();

    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&db_path)?;
    if version != DB_VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, DB_VERSION
        )));
    }

    let db_net = db_network(&db_path)?;
    if db_net != cosignerd.network {
        return Err(DatabaseError(format!(
            "Invalid network. Database is on '{}' but config says '{}'.",
            db_net, cosignerd.network
        )));
    }

    Ok(())
}

/// This integrity checks the database and creates it if it doesn't exist.
pub fn setup_db(cosignerd: &mut CosignerD) -> Result<(), DatabaseError> {
    let db_path = cosignerd.db_file();
    if !db_path.exists() {
        log::info!("No database at {:?}, creating a new one.", db_path);
        create_db(&cosignerd)?;
    }

    check_db(&cosignerd)?;

    Ok(())
}

/// Insert a signed outpoint into the database.
#[allow(clippy::too_many_arguments)]
pub fn db_insert_signed_outpoint(
    db_path: &PathBuf,
    signed_outpoint: OutPoint,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "INSERT INTO signed_outpoints (txid, vout) \
             VALUES (?1, ?2)",
            params![signed_outpoint.txid.to_vec(), signed_outpoint.vout],
        )
        .map_err(|e| DatabaseError(format!("Inserting signed outpoint: {}", e.to_string())))?;

        Ok(())
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{config::Config, cosignerd::CosignerD, utils::test_builder::CosignerTestBuilder};
    use revault_tx::{bitcoin::Network, transactions::RevaultTransaction};
    use serial_test::serial;
    use std::{fs, path::PathBuf};

    // Delete the database file
    fn clear_datadir(datadir_path: &PathBuf) {
        let mut db_path = datadir_path.clone();
        db_path.push("cosignerd.sqlite3");
        fs::remove_file(db_path).expect("Removing db path");
    }

    #[test]
    #[serial]
    fn test_db_creation() {
        let test_framework = CosignerTestBuilder::new(3).initialize().configure();
        let config =
            Config::from_file(Some(PathBuf::from("conf.toml"))).expect("Constructing Config");
        let mut cosignerd = CosignerD::from_config(config).expect("Constructing cosignerd state");
        println!("cosignerd.data_dir {:?}", cosignerd.data_dir);

        create_db(&mut cosignerd).unwrap();

        // We can't create it twice
        create_db(&mut cosignerd).unwrap_err();
        // The version is right
        check_db(&mut cosignerd).unwrap();
        // But it would not open a database created for a different network
        cosignerd.network = Network::Testnet;
        check_db(&mut cosignerd).unwrap_err();
        cosignerd.network = Network::Bitcoin;
        // Neither would it accept to open a database from the future!
        db_exec(&cosignerd.db_file(), |tx| {
            tx.execute(
                "UPDATE db_params SET version = (?1)",
                params![DB_VERSION + 1],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        check_db(&mut cosignerd).unwrap_err();

        clear_datadir(&cosignerd.data_dir);
    }

    #[test]
    #[serial]
    fn test_db_signed_outpoints() {
        let test_framework = CosignerTestBuilder::new(3).initialize().configure();
        let config =
            Config::from_file(Some(PathBuf::from("conf.toml"))).expect("Constructing Config");
        let mut cosignerd = CosignerD::from_config(config).expect("Constructing cosignerd state");

        create_db(&mut cosignerd).unwrap();

        let db_path = cosignerd.db_file();
        let spend_tx = test_framework.generate_spend_tx(4, 5);
        let outpoint = spend_tx.inner_tx().global.unsigned_tx.input[0].previous_output;

        db_insert_signed_outpoint(&db_path, outpoint).expect("Error inserting signed outpoint");

        clear_datadir(&cosignerd.data_dir);
    }
}
