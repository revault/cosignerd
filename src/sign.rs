use revault_tx::{
    miniscript::bitcoin::{OutPoint, Transaction, TxIn},
    transactions::SpendTransaction,
};
use crate::error::Error;

pub fn check_and_sign_spend_tx(db_path: &PathBuf, spend_tx: mut SpendTransaction) -> Result<SpendTransaction, Error> {
    // Determine which inputs can be signed for

    // Check that those inputs have expected addresses (given set of managers known from config)
    inputs_to_sign = Vec::new();

    // Check that none of those inputs have been signed before
    for input in spend_tx.global.unsigned_tx.input {
        let exists_result = db_signed_outpoint(db_path, &input.previous_output).map_error(|e| Error::Database(format!("Error while querying database for existence of outpoint: {:?}", e))?;
        if exists_result.is_some() {
            return Err(Error::SignOnlyOnce(format!("Input for given spend transaction has already been signed")));
        } else if exists_result.is_none() {
        // Sign transaction
            
        // Add each signed input as OutPoint to db
        }
    }

    // return signed spend tx

    unimplemented!()
}
