use revault_tx::miniscript::bitcoin::OutPoint;

pub const SCHEMA: &str = "\

CREATE TABLE db_params (
    version INTEGER NOT NULL
);

CREATE TABLE signed_outpoints (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    UNIQUE(txid, vout)
);

";

/// A row in the "signed_outpoints" table
pub struct DbSignedOutpoint {
    pub outpoint: OutPoint,
}
