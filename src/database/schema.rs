use revault_tx::miniscript::bitcoin::OutPoint;

pub const SCHEMA: &str = "\

CREATE TABLE db_params (
    version INTEGER NOT NULL
);

CREATE TABLE signed_outpoints (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    signature BLOB NOT NULL,
    UNIQUE(txid, vout)
);

";

/// A row in the "signed_outpoints" table
pub struct DbSignedOutpoint {
    pub outpoint: OutPoint,
    // We don't even take care of parsing it as a Signature, as we only input it with
    // to_der() and use it to insert in partial_sigs (which takes raw bytes)
    pub signature: Vec<u8>,
}
