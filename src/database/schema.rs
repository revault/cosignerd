use revault_tx::miniscript::bitcoin::OutPoint;

pub const SCHEMA: &str = "\

CREATE TABLE db_params (
    version INTEGER NOT NULL
);

CREATE TABLE signed_outpoints (
    txid BLOB UNIQUE NOT NULL,
    vout INTEGER NOT NULL
);

";

// A row in the "spend_transactions" table
pub struct DbSignedOutpoint {
    pub outpoint: OutPoint,
}
