mod schema;

use revault_tx::miniscript::bitcoin::{self, consensus::encode, OutPoint};
use rusqlite::{params, types::FromSqlError, Row, ToSql};
use schema::{DbSignedOutpoint, SCHEMA};
use std::{
    convert::{TryFrom, TryInto},
    fs,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

pub const DB_VERSION: u32 = 0;

#[derive(PartialEq, Eq, Debug)]
pub struct DatabaseError(pub String);

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Database error: {}", self.0)
    }
}

impl std::error::Error for DatabaseError {}

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &PathBuf, modifications: F) -> Result<(), DatabaseError>
where
    F: Fn(&rusqlite::Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = rusqlite::Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database: {}", e.to_string())))?;
    let tx = conn
        .transaction()
        .map_err(|e| DatabaseError(format!("Creating transaction: {}", e.to_string())))?;

    modifications(&tx)?;
    tx.commit()
        .map_err(|e| DatabaseError(format!("Comitting transaction: {}", e.to_string())))?;

    Ok(())
}

// Internal helper for queries boilerplate
fn db_query<'a, P, F, T>(
    path: &PathBuf,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: IntoIterator,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database for query: {}", e.to_string())))?;

    // rustc says 'borrowed value does not live long enough'
    let x = conn
        .prepare(stmt_str)
        .map_err(|e| DatabaseError(format!("Preparing query: '{}'", e.to_string())))?
        .query_map(params, f)
        .map_err(|e| DatabaseError(format!("Mapping query: '{}'", e.to_string())))?
        .collect::<rusqlite::Result<Vec<T>>>()
        .map_err(|e| DatabaseError(format!("Executing query: '{}'", e.to_string())));

    x
}

/// Get the database version
pub fn db_version(db_path: &PathBuf) -> Result<u32, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT version FROM db_params", params![], |row| {
        row.get::<_, u32>(0)
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))
}

impl TryFrom<&Row<'_>> for DbSignedOutpoint {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let txid: bitcoin::Txid = encode::deserialize(&row.get::<_, Vec<u8>>(0)?)
            .map_err(|e| FromSqlError::Other(Box::new(e)))?;
        let outpoint = OutPoint {
            txid,
            vout: row.get(1)?,
        };

        Ok(DbSignedOutpoint { outpoint })
    }
}

/// Check for existence of signed outpoint in the database. If it
/// doesn't exist, returns Ok(None). Returns Ok(Some(DbSignedOutpoint))
/// if it does exist.
pub fn db_signed_outpoint(
    db_path: &PathBuf,
    signed_outpoint: &OutPoint,
) -> Result<Option<DbSignedOutpoint>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM signed_outpoints WHERE txid = (?1) AND vout = (?2)",
        params![signed_outpoint.txid.to_vec(), signed_outpoint.vout],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Insert a signed outpoint into the database.
pub fn db_insert_signed_outpoint(
    db_path: &PathBuf,
    signed_outpoint: &OutPoint,
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

// Create the SQLite database. This creates a file with 600 perms and creates the SCHEMA, then
// initializes the version.
fn create_db(db_path: &PathBuf) -> Result<(), DatabaseError> {
    // Rusqlite could create it for us, but we want custom permissions
    create_db_file(db_path)
        .map_err(|e| DatabaseError(format!("Creating db file: {}", e.to_string())))?;

    db_exec(db_path, |tx| {
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
fn check_db(db_path: &PathBuf) -> Result<(), DatabaseError> {
    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(db_path)?;
    if version != DB_VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, DB_VERSION
        )));
    }

    Ok(())
}

/// This integrity checks the database and creates it if it doesn't exist yet.
pub fn setup_db(db_path: &PathBuf) -> Result<(), DatabaseError> {
    if !db_path.exists() {
        log::info!("No database at {:?}, creating a new one.", db_path);
        create_db(db_path)?;
    }

    check_db(db_path)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::builder::CosignerTestBuilder;
    use serial_test::serial;
    use std::str::FromStr;

    #[test]
    #[serial]
    fn db_creation_sanity() {
        let test_framework = CosignerTestBuilder::new(3);
        let db_path = &test_framework.cosignerd.db_file();

        // We can't create it twice
        create_db(db_path).unwrap_err();
        // The version is right
        check_db(db_path).unwrap();
        // It would not accept to open a database from the future!
        db_exec(db_path, |tx| {
            tx.execute(
                "UPDATE db_params SET version = (?1)",
                params![DB_VERSION + 1],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        check_db(db_path).unwrap_err();
    }

    #[test]
    #[serial]
    fn signed_outpoints_insertion_sanity() {
        let test_framework = CosignerTestBuilder::new(7);

        let db_path = test_framework.cosignerd.db_file();
        let outpoint = OutPoint::from_str(
            "e69a8de68c69b2f19249437004b65e82e2615c61c8d852fd36965c032a117d00:120",
        )
        .unwrap();

        db_insert_signed_outpoint(&db_path, &outpoint).expect("Error inserting signed outpoint");
        db_signed_outpoint(&db_path, &outpoint).expect("");
    }
}
