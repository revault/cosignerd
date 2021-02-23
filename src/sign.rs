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

// Routine for ""signing"" a transaction
fn satisfy_transaction_input(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    tx: &mut impl RevaultTransaction,
    input_index: usize,
    tx_sighash: &SigHash,
    xprivs: &Vec<bip32::ExtendedPrivKey>,
    child_number: Option<bip32::ChildNumber>,
    sighash_type: SigHashType,
) -> Result<(), Error> {
    let derivation_path = bip32::DerivationPath::from(if let Some(cn) = child_number {
        vec![cn]
    } else {
        vec![]
    });

    for xpriv in xprivs {
        let sig = (
            secp.sign(
                &secp256k1::Message::from_slice(&tx_sighash).unwrap(),
                &xpriv
                    .derive_priv(&secp, &derivation_path)
                    .unwrap()
                    .private_key
                    .key,
            ),
            sighash_type,
        );

        let xpub = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, xpriv),
            derivation_path: bip32::DerivationPath::from(vec![]),
            is_wildcard: child_number.is_some(),
        });
        let xpub_ctx = DescriptorPublicKeyCtx::new(
            &secp,
            // If the xpub is not a wildcard, it's not taken into account.......
            child_number.unwrap_or_else(|| bip32::ChildNumber::from(0)),
        );
        tx.add_signature(input_index, xpub.to_public_key(xpub_ctx), sig)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, cosignerd::CosignerD, utils::test_builder::CosignerTestBuilder};

    #[test]
    fn test_satisfy_transaction_input() {
        let test_framework = CosignerTestBuilder::new(3, 4).initialize().configure();
        let config =
            Config::from_file(Some(test_framework.get_config_path())).expect("Constructing Config");
        let cosignerd = CosignerD::from_config(config).expect("Constructing cosignerd state");
        
        let spend_tx = test_framework.generate_spend_tx(5, 1);

        // TODO: 

    }
}
