use crate::{
    config::Config,
    database::{db_insert_signed_outpoint, db_signed_outpoint, DatabaseError},
};

use revault_net::message::cosigner::{SignRequest, SignResult};
use revault_tx::{
    bitcoin::{secp256k1, PublicKey as BitcoinPubkey, SigHashType},
    error::InputSatisfactionError,
    transactions::RevaultTransaction,
};

#[derive(Debug)]
pub enum SignProcessingError {
    Database(DatabaseError),
    // FIXME: we should upstream the iteration over inputs as we can safely panic there.
    InsanePsbtMissingInput(InputSatisfactionError),
}

impl std::fmt::Display for SignProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::InsanePsbtMissingInput(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for SignProcessingError {}

fn null_signature() -> SignResult {
    SignResult { tx: None }
}

/// This implements the main logic of the Cosigning Server. Acting as a dead-simple anti-replay
/// oracle it signs any incoming Spend transaction if all of its outpoints were not signed already.
/// See https://github.com/revault/practical-revault/blob/master/messages.md#sign
pub fn process_sign_message(
    config: &Config,
    sign_msg: SignRequest,
    bitcoin_privkey: &secp256k1::SecretKey,
) -> Result<SignResult, SignProcessingError> {
    let db_path = config.db_file();
    let mut spend_tx = sign_msg.tx;

    if spend_tx.is_finalized() {
        return Ok(null_signature());
    }

    // If any of the inputs was already signed, return null
    for txin in spend_tx.inner_tx().global.unsigned_tx.input.iter() {
        if db_signed_outpoint(&db_path, &txin.previous_output)
            .map_err(SignProcessingError::Database)?
            .is_some()
        {
            return Ok(null_signature());
        }

        // NOTE: we initially decided to check each manager's signature here, and then we discarded
        // it. This is still being discussed whether it's fine to drop this check...
    }

    // If we never signed it yet, append our signatures to the PSBT
    let secp = secp256k1::Secp256k1::signing_only();
    let our_pubkey = BitcoinPubkey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, bitcoin_privkey),
    };
    let mut psbtins = spend_tx.inner_tx_mut().inputs.clone(); // borrow checker forces a clone..
    for (i, psbtin) in psbtins.iter_mut().enumerate() {
        // FIXME: sighash cache upstream...
        let sighash = spend_tx
            .signature_hash_internal_input(i, SigHashType::All)
            .map_err(SignProcessingError::InsanePsbtMissingInput)?;
        let sighash = secp256k1::Message::from_slice(&sighash).expect("Sighash is 32 bytes");
        let mut signature = secp
            .sign(&sighash, bitcoin_privkey)
            .serialize_der()
            .to_vec();
        signature.push(SigHashType::All as u8);
        assert!(
            psbtin.partial_sigs.insert(our_pubkey, signature).is_none(),
            "If there was a signature for our pubkey already and we didn't return \
             above, we have big problems.."
        );

        db_insert_signed_outpoint(
            &db_path,
            &spend_tx.inner_tx().global.unsigned_tx.input[i].previous_output,
        )
        .map_err(SignProcessingError::Database)?;
    }
    spend_tx.inner_tx_mut().inputs = psbtins;

    Ok(SignResult { tx: Some(spend_tx) })
}

#[cfg(test)]
mod test {
    use crate::{processing::process_sign_message, tests::builder::CosignerTestBuilder};
    use revault_net::message::cosigner::*;
    use revault_tx::{bitcoin::OutPoint, transactions::RevaultTransaction};
    use std::str::FromStr;

    #[test]
    fn sign_message_processing_sanity_check() {
        let test_framework = CosignerTestBuilder::new(3);

        let duplicated_outpoint = OutPoint::from_str(
            "2b8930127e9dfd1bcdf35df2bc7f3b8cdbec083b1ae693f36b6305fccd1425da:0",
        )
        .unwrap();

        let tx = test_framework.generate_spend_tx(&[
            duplicated_outpoint,
            OutPoint::from_str(
                "ceca4de398c63b29543f8346c09fd7522fd8661ce8bdc0e454e8d6ed8ad46a0d:1",
            )
            .unwrap(),
            OutPoint::from_str(
                "0b38682347207cd79de33edf8897a75abe7d8799b194439150306773b6aef55a:189",
            )
            .unwrap(),
        ]);
        assert_eq!(
            tx.inner_tx()
                .inputs
                .iter()
                .map(|i| i.partial_sigs.len())
                .sum::<usize>(),
            0
        );
        let sign_a = SignRequest { tx };
        let SignResult { tx } = process_sign_message(
            &test_framework.config,
            sign_a,
            &test_framework.bitcoin_privkey,
        )
        .unwrap();
        assert_eq!(
            tx.unwrap()
                .inner_tx()
                .inputs
                .iter()
                .map(|i| i.partial_sigs.len())
                .sum::<usize>(),
            3
        );

        let tx = test_framework.generate_spend_tx(&[
            duplicated_outpoint,
            OutPoint::from_str(
                "d907a6733fba14884d7de578d0536bf32c8fa96ec2dce9d04d2bcf8bddbd540a:1",
            )
            .unwrap(),
            OutPoint::from_str(
                "07b467b293c8a1202677a5f0b1ba4f1ee0ae70ac1abdffbdd5375b07e0016d92:120",
            )
            .unwrap(),
        ]);
        let sign_a = SignRequest { tx };
        let SignResult { tx } = process_sign_message(
            &test_framework.config,
            sign_a,
            &test_framework.bitcoin_privkey,
        )
        .unwrap();
        assert!(tx.is_none(), "It contains a duplicated outpoint");
    }
}
