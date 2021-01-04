use crate::database::{schema::DbSignedOutpoint, DatabaseError};
use revault_tx::bitcoin::{consensus::encode, Network, OutPoint, Txid};

use std::{
    boxed::Box,
    convert::{TryFrom, TryInto},
    path::PathBuf,
    str::FromStr,
};

use rusqlite::{params, types::FromSqlError, Connection, Row, ToSql, Transaction, NO_PARAMS};

// Note that we don't share a global struct that would contain the connection here.
// As the bundled sqlite is compiled with SQLITE_THREADSAFE, quoting sqlite.org:
// > Multi-thread. In this mode, SQLite can be safely used by multiple threads provided that
// > no single database connection is used simultaneously in two or more threads.
// Therefore the below routines create a new connection and can be used from any thread.

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &PathBuf, modifications: F) -> Result<(), DatabaseError>
where
    F: Fn(&Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = Connection::open(path)
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
    let conn = Connection::open(path)
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
    let mut rows = db_query(db_path, "SELECT version FROM db_params", NO_PARAMS, |row| {
        row.get::<_, u32>(0)
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))
}

/// Get the network this DB was created on
pub fn db_network(db_path: &PathBuf) -> Result<Network, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT network FROM db_params", NO_PARAMS, |row| {
        Ok(Network::from_str(&row.get::<_, String>(0)?)
            .expect("We only evert insert from to_string"))
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in db_params table?".to_string()))
}

impl TryFrom<&Row<'_>> for DbSignedOutpoint {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(0)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        cosignerd::CosignerD,
        database::actions::{create_db, db_insert_signed_outpoint},
        utils::test_builder::CosignerTestBuilder,
    };
    use revault_tx::transactions::RevaultTransaction;
    use serial_test::serial;
    use std::fs;

    // Delete the database file
    fn clear_datadir(datadir_path: &PathBuf) {
        let mut db_path = datadir_path.clone();
        db_path.push("cosignerd.sqlite3");
        fs::remove_file(db_path).expect("Removing db path");
    }

    #[test]
    #[serial]
    fn name() {
        let test_framework = CosignerTestBuilder::new(3).initialize().configure();
        let config =
            Config::from_file(Some(PathBuf::from("conf.toml"))).expect("Constructing Config");
        let mut cosignerd = CosignerD::from_config(config).expect("Constructing cosignerd state");
        create_db(&mut cosignerd).unwrap();

        let db_path = cosignerd.db_file();
        let spend_tx = test_framework.generate_spend_tx(4, 5);
        let outpoint = spend_tx.inner_tx().global.unsigned_tx.input[0].previous_output;

        db_insert_signed_outpoint(&db_path, outpoint.clone())
            .expect("Error inserting signed outpoint");

        db_signed_outpoint(&db_path, &outpoint)
            .expect("Error while querying db for signed_outpoint");

        clear_datadir(&cosignerd.data_dir);
    }
}
