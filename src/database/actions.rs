use crate::{
    cosignerd::CosignerD,
    database::{interface::*, schema::SCHEMA, DatabaseError, DB_VERSION},
};
use revault_tx::miniscript::bitcoin::OutPoint;
use rusqlite::params;
use std::{fs, os::unix::fs::OpenOptionsExt, path::PathBuf};

// Create the db file with RW permissions only for the user
fn create_db_file(db_path: &PathBuf) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(db_path)?;

    Ok(())
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
            "INSERT INTO db_params (version) VALUES (?1)",
            params![DB_VERSION],
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
        let mut test_framework = CosignerTestBuilder::new(3);

        create_db(&mut test_framework.cosignerd).unwrap();

        // We can't create it twice
        create_db(&mut test_framework.cosignerd).unwrap_err();
        // The version is right
        check_db(&mut test_framework.cosignerd).unwrap();
        // Neither would it accept to open a database from the future!
        db_exec(&test_framework.cosignerd.db_file(), |tx| {
            tx.execute(
                "UPDATE db_params SET version = (?1)",
                params![DB_VERSION + 1],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        check_db(&mut test_framework.cosignerd).unwrap_err();

        clear_datadir(&test_framework.cosignerd.data_dir);
    }

    #[test]
    #[serial]
    fn test_db_signed_outpoints() {
        let mut test_framework = CosignerTestBuilder::new(7);
        create_db(&mut test_framework.cosignerd).unwrap();

        let db_path = test_framework.cosignerd.db_file();
        let spend_tx = test_framework.generate_spend_tx(4, 3, 98);
        let outpoint = spend_tx.inner_tx().global.unsigned_tx.input[0].previous_output;

        db_insert_signed_outpoint(&db_path, outpoint).expect("Error inserting signed outpoint");

        clear_datadir(&test_framework.cosignerd.data_dir);
    }
}
