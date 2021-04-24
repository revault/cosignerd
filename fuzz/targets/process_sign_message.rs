use cosignerd::{
    self,
    database::db_signed_outpoint,
    revault_net::message::cosigner::SignRequest,
    revault_tx::transactions::{RevaultTransaction, SpendTransaction},
};
use honggfuzz::fuzz;

fn main() {
    let builder = cosignerd::tests::builder::CosignerTestBuilder::new(10);
    let db_path = builder.config.db_file();

    loop {
        fuzz!(|data: &[u8]| {
            if let Ok(tx) = SpendTransaction::from_psbt_serialized(data) {
                let prevouts: Vec<_> = tx
                    .inner_tx()
                    .global
                    .unsigned_tx
                    .input
                    .iter()
                    .map(|txin| txin.previous_output)
                    .collect();

                let sigs_list: Vec<_> = tx
                    .inner_tx()
                    .inputs
                    .iter()
                    .map(|psbtin| psbtin.partial_sigs.clone())
                    .collect();

                let is_finalized = tx.is_finalized();

                let msg = SignRequest { tx };
                let resp = cosignerd::processing::process_sign_message(
                    &builder.config,
                    msg,
                    &builder.bitcoin_privkey,
                )
                .expect("We should never crash while processing a message");

                if let Some(resp_tx) = resp.tx {
                    let psbt = resp_tx.inner_tx();

                    for (i, sigs) in sigs_list.into_iter().enumerate() {
                        assert!(psbt.inputs[i].partial_sigs.len() == sigs.len() + 1);
                    }

                    for txin in psbt.global.unsigned_tx.input.iter() {
                        assert!(db_signed_outpoint(&db_path, &txin.previous_output)
                            .unwrap()
                            .is_some());
                    }
                } else if !is_finalized{
                    let n_signed = prevouts
                        .iter()
                        .filter_map(|prevout| db_signed_outpoint(&db_path, &prevout).unwrap())
                        .count();
                    assert!(n_signed > 0 && n_signed < sigs_list.len());
                }
            }
        });
    }
}
