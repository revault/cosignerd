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
    // They sent us an insane transaction. FIXME: these checks should be part of revault_tx!
    Garbage,
    // FIXME: we should upstream the iteration over inputs as we can safely panic there.
    InsanePsbtMissingInput(InputSatisfactionError),
}

impl std::fmt::Display for SignProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::Garbage => write!(f, "We were sent an insane Spend transaction"),
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
    let secp = secp256k1::Secp256k1::signing_only();
    let our_pubkey = BitcoinPubkey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, bitcoin_privkey),
    };
    let mut spend_tx = sign_msg.tx;
    let n_inputs = spend_tx.inner_tx().global.unsigned_tx.input.len();

    // If it's finalized already, we won't be able to compute the sighash
    if spend_tx.is_finalized() {
        return Err(SignProcessingError::Garbage);
    }

    // Gather what signatures we have for these prevouts
    let mut signatures = Vec::with_capacity(n_inputs);
    for txin in spend_tx.inner_tx().global.unsigned_tx.input.iter() {
        if spend_tx
            .inner_tx()
            .global
            .unsigned_tx
            .input
            .iter()
            .filter_map(|curr| {
                if curr.previous_output == txin.previous_output {
                    Some(curr)
                } else {
                    None
                }
            })
            .count()
            > 1
        {
            return Err(SignProcessingError::Garbage);
        }

        if let Some(signed_op) = db_signed_outpoint(&db_path, &txin.previous_output)
            .map_err(SignProcessingError::Database)?
        {
            signatures.push(signed_op.signature)
        }

        // NOTE: we initially decided to check each manager's signature here, and then we discarded
        // it. This is still being discussed whether it's fine to drop this check...
        // We later stripped the managers signatures from the PSBT before sharing it, in order to
        // not hit the Noise message size limit. Hence the above is unlikely to happen anytime
        // soon..
    }

    // If we had all the signatures for all these outpoints, send them. They'll figure out whether
    // they are valid or not.
    if signatures.len() == n_inputs {
        for (i, mut sig) in signatures.into_iter().enumerate() {
            sig.push(SigHashType::All as u8);
            spend_tx.inner_tx_mut().inputs[i]
                .partial_sigs
                .insert(our_pubkey, sig);
        }
        return Ok(SignResult { tx: Some(spend_tx) });
    }

    // If we already signed some of the outpoints, don't sign anything else!
    if !signatures.is_empty() {
        return Ok(null_signature());
    }

    // If we signed none of the input, append fresh signatures for each of them to the PSBT.
    let mut psbtins = spend_tx.inner_tx().inputs.clone();
    for (i, psbtin) in psbtins.iter_mut().enumerate() {
        // FIXME: sighash cache upstream...
        let sighash = spend_tx
            .signature_hash_internal_input(i, SigHashType::All)
            .map_err(SignProcessingError::InsanePsbtMissingInput)?;
        let sighash = secp256k1::Message::from_slice(&sighash).expect("Sighash is 32 bytes");

        let signature = secp.sign(&sighash, bitcoin_privkey);
        let mut raw_sig = signature.serialize_der().to_vec();
        raw_sig.push(SigHashType::All as u8);
        assert!(
            psbtin.partial_sigs.insert(our_pubkey, raw_sig).is_none(),
            "If there was a signature for our pubkey already and we didn't return \
             above, we have big problems.."
        );

        db_insert_signed_outpoint(
            &db_path,
            &spend_tx.inner_tx().global.unsigned_tx.input[i].previous_output,
            &signature,
        )
        .map_err(SignProcessingError::Database)?;
    }
    spend_tx.inner_tx_mut().inputs = psbtins;

    // Belt-and-suspender: if it was not empty, we would have signed a prevout twice.
    assert!(signatures.is_empty());

    Ok(SignResult { tx: Some(spend_tx) })
}

#[cfg(test)]
mod test {
    use crate::{processing::process_sign_message, tests::builder::CosignerTestBuilder};
    use revault_net::message::cosigner::*;
    use revault_tx::{
        bitcoin::OutPoint,
        transactions::{RevaultTransaction, SpendTransaction},
    };
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
            sign_a.clone(),
            &test_framework.bitcoin_privkey,
        )
        .unwrap();
        let tx = tx.unwrap();
        assert_eq!(
            tx.inner_tx()
                .inputs
                .iter()
                .map(|i| i.partial_sigs.len())
                .sum::<usize>(),
            3
        );

        // Now if we ask for the same outpoints again, they'll send the very same PSBT
        let SignResult { tx: second_psbt } = process_sign_message(
            &test_framework.config,
            sign_a,
            &test_framework.bitcoin_privkey,
        )
        .unwrap();
        assert_eq!(tx, second_psbt.unwrap());

        // However, if the set of inputs is different they wont be happy
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

    #[test]
    fn fuzzer_findings() {
        let test_framework = CosignerTestBuilder::new(3);
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAOICAAAABCqeuW7WKzo1iD/mMt74WOi4DJRupF8Ys2QTjQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADxZt3WVCjfgjKELfnCbE7VhDEwBNxxAAAAAAA1AAAAAgBtAgAAAAAAIgAg0Gj3W+Rd1ot6j+P41DvKm8cxffTqb5d16itMgf92OhABAAAAAAAAAAAAAAAAAAEBK1gbAAAAAAAAIgAgojcWQ/3MIpoGMhKAwimEh5JuiGDwcTwvxbbn0u9yCm0iAgI9PBGGf8vO7+biuCwXIwyMcl/WnXjHNcgONQlw6rQ8RkcwRAIgBC9dlhm+IJF/JCIxBlY/XNc7Hk9FwWl8v4qM+/cYBK0CIG4M/J9wIU8x/yEGnUfw/////////3eA1cUifH1aQTwpASICA1L8WQgospLJ5VH1KD4qQriEeCSiImGwkthmqIWYI1xwRzBEAiASrMj/Oe7GnTuMrXJkygfGrkYI7XtNBtEYjXFEu2kWqgIgXo/vr5I5kXzm+L/VYn6lVDcuQy6o/0GzdR7hwYMx1O8BIgICdWdm3jiS5ZPHKNnqi5SYNUEaR+15VE11wb78yh8DlpRIMEUCIQDWQyaNI1g0NjAAEo6N4I4hcOCjQJiJwYrxa3m1kyQoeAIgadbad2iooERlY1nmn1gZBh8bq1SRLdOoHX+8JxiC5DcBAQMEAQAAAAEFqSEDUvxZCCiyksnlUfUoPipCuIR4JKIiYbCS2GaohZgjXHCsUYdkdqkUxhZiI/YGY2gj8umzPtokdTJNuhuIrGt2qRQW/9zsUV6nc+rRgu8qX20+zj7omIisbJNSh2dSIQJ1Z2beOJLlk8co2eqLlJg1QRpH7XlUTXXBvvzKHwOWlCECPTwRhn/Lzu/m4rgsFyMMjHJf1p14xzXIDjUJcOq0PEZSrwE1smgAAQErWBsAEQAAAAAiACCiNxZD/cwimgYyEoDCKYSHkm6IYPBxPC/FtufS73IKbSICAj08EYZ/y87v5uK4LBcjDIxyX9adeMc1yA41CXDqtDxGSDBFAiEAxXAAAAAAAAAAgQPzJcM9PATklkmXKRLViIP5996WGpcCIGjh0vgla8BMl721eIwGsk9gkyPKbpnBauUmdyTNPUqEASICA1L8WQgospLJ5VH1KD4qQriEeCSiImGwkthmqIWYI1xwSDBFAiEA09Pt+ccX3ObhgFqCzGeHH0tDvF94F6ttZOM+TTIr900CICQImMl+XA8rdhnZ3IdBlewgqoTxVDOlCmpZK2AMR4FzASICAnVnZt44kuWTxyjZ6ouUmDVBGkfteVRNdcG+/MofA5aUSDBFAiEA/esuvPH25/j3lGo0OwQnEKsMXZqersB4J0vauRfDuaoCIHCowrDm9T9Ua79yeYfhyT5rVEuXoF8jU3gQzNzqLIWqAQEDBAEAAAABBakhA1L8WQgospLJ5VH1KD4qQriEeCSiImGwkthmqIWYI1xwrFGHZHapFMYWYiP2BmNoI/Lpsz7aJHUyTbobiKxrdqkUFv/c7FFep3Pq0YLvKl9tPs4+6JiIrGyTUodnUiECdWdm3jiS5ZPHKNnqi5SYNUEaR+15VE11wb78yh8DlpQhAj08EYZ/y87v5uK4LBcjDIxyX9adeMc1yA41CXDqtDxGUq8BNbJoAAEBK1gbAAAAAAAAIgAgojcWQ/3MIpoGMhKAwimEh5JuiGDwcTwvxbbn0u9yCm0iAgI9PBGGf8vO7+biuCwXIwyMcl/WnXjHNcgONQlw6rQ8RkgwRQIhAIuWO0cWDTlO4B3eWOLK2A3uDVCDb8BDTL2fY9zyQY95AiAdkmyAqJ2M+jQN26tYVrM6GuCbGPFGpxsjmXdNg2TNGQEiAgNS/FkIKLKSyeVR9Sg+KkK4hHgkoiJhsJLYZqiFmCNccEcwRAIgWGDjwMt7ngtcE4AsFOzUU5KYQrx4EZ4+Rbw7NT+McLYCIEvl6RQkAknX6qWu+0qIplOROYhOcZffP6jYsFgWLASCASICAnVnZt44kuWTxyjZ6ouUmDVBGkfteVRNdcG+/MofA5aUSDBFAiEAtrVqNs4k8kn9olyodZbkLjJzQyCDASlJWOQ230/GAywCIBf2tjSepjt1gnFvrK5d6vGTSPfVd5FKfASOpCgXXiaLAQEDBAEAAAABBakhA1L8WQgospLJ5VH1KD4qQriEeCSiImGwkthmqIWYI1xwrFGHZHapFMYWYiP2BmNoI/Lpsz7aJHUyTbobiKxrdqkUFv/c7FFep3Pq0YLvKl9tPs4+6JiIrGyTUodnUiECdWdm3jiS5ZPHKNnqi5SYNUEaR+15VE11wb78yh8DlpQhAj08EYZ/y87v5uK4LBcjDIxyX9adeMc1yA41CXDqtDxGUq8BNbJoAAEBK1gbAAAAAAAAIgAgojcWQ/3MIpoGMhKAwimEh5JuiGDwcTwvxbbn0u9yCm0iAgI9PBGGf8vO7+biuCwXIwyMcl/WnXjHNcgONQlw6rQ8RkgwRQIhAKXrLaWYniEbBBPRfbNv7w5tus1hr5Cgft9XlenBZ5qDAiB/pzvS1lHGUn17UdPJXq4FrGP3y3fM/iOqIhl+KWFUrQEiAgNS/FkIKLKSyeVR9Sg+KkK4hHgkoiJhsJLYZqiFmCNccEgwRQIhALPMWpxFF/l3mxSgIFeHArrv4FI2P4ePySRAN9NG4kenAiBDSROyN6CDcU9QV9gSQ3NojTqrv4F52ALkgpNPYPSKGQEiAgJ1Z2beOJLlk8co2eqLlJg1QRpH7XlUTXXBvvzKHwOWlEgwRQIhANuzYY/9RDTPKIRl+EdriHrByDRKo5c4VCUREiKSRABEAiAGH2rLEu6yELFX0xj0LsYRKuCCFnO1TaYdhYaT2c8yYQEBAwQBAAAAAQWpIQNS/FkIKLKSyeVR9Sg+KkK4hHgkoiJhsJLYZqiFmCNccKxRh2R2qRTGFmIj9gZjaCPy6bM+2iR1Mk26G4isa3apFBb/3OxRXqdz6tGC7ypfbT7OPuiYiKxsk1KHZ1IhAnVnZt44kuWTxyjZ6ouUmDVBGkfteVRNdcG+/MofA5aUIQI9PBGGf8vO7+biuCwXIwyMcl/WnXjHNcgONQlw6rQ8RlKvATWyaAABASUhvUXMToEbCgIgXW7CJmwULnODIByn3UEdQ17Tw70zzkujV0+kXnYLAzMBRzBEQiBY9+oiDdkeMlFvvjQOamJUE09h6kRoko0zIMEcf5xbqgIgYUEZZbp3oJeD5/5lehX+Nl/0w+Qge0B5lsb1dSGwd1b8i7w9mfTvfgGrIQMVW/CEt8gDUJwllTrk+vo8cPTRom/akjsZqTAawW7lWqxRh2R2qRTPCxUS8REPlsw0ko4TvVJtyGPpXIisa3apFM9qV5JGPLlrZ6/EWc/egVPCKjHTiKxsk1KHdighAgJDDShqHBrdYIASGPgX1/w5/WUT7O6gp2qz2a1It8AnIQN3dtuQUq6DeXtoprPBAF4dZcBXzp409tU8tOSEBHfxVlKvAw/vALJoAAEBK1gbAAAAAAAAIgAgnF2ChVYxm7/b3Qd+K8nqeHzBWye8XzqGEYc3/9QuisgBCP2IAQUARzBEAiBDSLzf+EGoIyEHFJu7UKZMV9nJmeEW6w/EUmk1SoO3fwIgQsTaYC6ZKgGJoIYomlPL9FqTSMU5B2r3/yB48+eVuSwBSDBFAiEAouIAJvm9poo4lv5wBoLT5N5znR/+UQ3DtiHmIAEAAAACIG3lt20bJBcPPKJtaO1matrhJ6PExC6yCDz1cUaitVaQAUgwRQIhAL9z7lH05Qqyhzfx9dhGYBYTI8ndYiSzyN91VYDvljv5AiBAKzD3JnFMcRhOehN6hbJSYT9tGggB6NZe7zWxx6LR6gGrIQMVW/CEt8gDUJwllTrk+vo8cPTuv6fLLI8BMv0iDnJcOVnUqIZJeLd/+jMZxLxIIiEDgxW2rHUdWyGjzRuNBLipgoMGg7KCdhHAYSoop78x8RIhA03ro08EnhvX75HcUlbgk+EuChXGu72TDFJtvIcrMep7IQIt00409KIiYbCS2GaohZgjXHCsUYcAAC2vhaSFQOwZM5Jw9KFCnoWpXJkwG54jqKJPoCEDa0HZfVPHJMvIwW1BOuO57RXoAxRaLn/c3vG3Ou/fOHohA6gtR/hfjnbg14XfcbkShu7CVOsMQxR0Kp65btYrOjWIP+Yy3vhY6LgMlG6kXxizZBON/hTc1w4AAAAAAA/vAAA6M+wDryMM9a5GPCtkXwA3U7+wbagHsCuJQokyy8+qIwEAAAAAD+8AAB2bBaoyEG67bPEq76ERXFQbYYR6qXgjoEvkt3dAv8r8AAAAAAAP7wAA4QqDhK577RSBAPEy3dZUKN93zXvS+cJsTtWEMTAE3HEAAAAAAA/vAAACAG8CAAAAAAAiACAqqFrxCsAa70fpKI4v37IIbcLPcclhjsHd3IErMn2qKwEAAAAAAAAAAAAAAAAAAQErWBsAAAAAAAAiACCcXYKFVjSbv9vdB34ryep4fMFbJ7xfOoYRhzf/1C6KyAEI/YYBBQBHMEQCIDyo5zPrShdh8MDpWK33v4F/opM+zoMnnQ+9RcxOgRsKAiBdbsImbBQuc4MgHKfdQR1DXtPDvTPOS6NXT6ReAAAAAAAAAHB2CwMzAUcwREIgWPfqIg3ZHjJRb740DmpiVBNPYepEaJKNNCDBcHNidP8BAIcCAAAAAmGiP5JDhf1ZQb0GIFozmhHaxTIbglcnkUNV29AZwmzYAAAAAAD9//87clv6iDVOAJj64ylu+Y2zdrBL1u+aBo/agQ1ek2C8NDM3OAAAAP3///8B0soC////FAAiACDQnoAebEb9K9sITUle7d2eHou2480DqmRBbhvEhTjtLwAAAAAAIgYCLr+ali2zUlMVtaqZd82JbAfztpj5ORJ1eiGx2mE/D7QEAAABBStADQN27t0g3fjtAl4pcnTMCUiWgTAs3gpRrgzHnrzGZAsnZTPurDuPoRRIACIGAi6/mpYts1JTFbWqmXfNiWwH8xL64ylu+Y2zdrBL1u+aBCIGAi6/mpYtrDuPoRRIACIcf5xbqgIgYUEZZbp3nZeD5/5lehX+KTZf9MPkIHtAeXmj/aQH1IisbJNSh2dSIQICQw0oahwa3WCAEhj4FxxU8jF/vIKcB1x11FA7EXEaLFpJO6dSPonU8f5GX+v7AiA6dIOxzv4brC0j+vyjMMMX2/JraoJ7p4TJfnn/h9eMEbeBIQNDYB8F0yvyc5BLbuMQNdLBABDLEMZz5mrPbb9F+bP0CEcwRAIgAlaTe9eIUSwC9X+UnrgwfXEvQl4e4FaOEOxTe2mOgUECIEepNJRXERsPcPArpo9PnR5JwNXK4wgQ/f+8FhXJK+/IgSECtpmpeQCtKWOKpw9f00s56qjFp6FnkiWhkYB4RxO1LSlHMEQCIHbDCV5tiT42bgQKUnMfbfc6tUCR5q3rN0Hb/sgWOUjqAiBw5ygLaDop8bYjvdcFJkTSeGO86D8t6ojssEaDfoLCVoEhAw0jFmP4HfgE3qjTPMM23NkDaJI/GYDoelhDQV2uxNKTSDBFAiEA9wHp9Z0JwVm3bBIEx8/p5hpwM1uOGljxm574SRQj6tUCIB2pxGLJTH3nDJOpcQOy+dCz4K0O+40OAAAAAAAAAMnHgSEDbbusZjSSuFdLws9tQw/gAQziDkmmOZjC8pGg3Fps8iFIMUUCIQC2iH6wMdCVk+/fmCnyn2wVCmnBs8drx9j7cJVjWI+rBAIgOdnr65A9h8Y0axyEcGK8kom97YMqMN7a+I5dn7pNKNKBIQIRxsa/vlkH1sscRVJb5eD5Hvm8rKijoCej4AAAAAAAgAAAd5paLG9ARzBEAiBP6UNCpBwngxLf24j2zwMgd7MpEHpNg6/RPeSHxo7hCAIgIzP8paQKdEkMTlNbtr4jCDmo47TKIcvxdLHKMuJ7uneBIQO8OK2eeL5zQpiqAg/TflyZXLCLN3Gu5XksVzHa6iX890cwRAIgBp+THcl7Jvb4bV6UNMWzQI9tfuCZQ2sUPFcm6YqBrrMCIBtIvw0c+6FUkXmzzZZfRRvwE5HF9qx3m7NzbvjZvJxYgSECUTgcSJzz6LhHp+UgpsdockBbQNXS3oqsW7tnZ/GTGkJHMEQCIFH7cagR697codHvMuFyhluNxTBbo7rwM2tE1JnJw/ItAiAsO0aIDpAuXSRo001VCjCUXd+JotKfbP0AwQYV6k7FVIEhAjr8UBqKEx0BSqMzcvn7X43X7Wvy5y7uEHGFz/IZjsygSDBFAiEA8d2DUcZHBCkyh3x3aDIAAAAAAAAACMRNJhtlBiQ5S64CIFv/KjIC0V7zPkyIHRB/6m5K/Wj+ahgqJp/qhh2+sDVggSEC+4SrF4JpRDVfPLxRRsSdz5wr0rKim98Wg5SyHtJSWwAAAAAAAAAUGkcwRAIgaSI/goNxMqoLA8rj3DLAzOZiDsMXtgp20B+tgU2beS4CIOY3Hsr0p6MjD9XVnRyl88AaTnza4dXIoYTU1YTXUO2RgSEDHf+7EWCsmmeQ6y+dhSsM0r5cYoSAsbuMPaVJozBqSDBFAiEAx+89LaYSaUuU2oREPLSLubdFRqYmvPwCPT4IK91mysMCIDlAAAAAAAAAAGmSWdoeQKODTa16/d4LnwEqGpXAJyJMgSEC+MmaWiNQ/QjZ184Ln6Vivs+2HbKyHicBQ5ax5h9ZDGBIMEUCIQCqCUBD38an8MNgsof2SBzclCO25QK87Rj1vINkOcaBvAIgM08Ph+KA5JYbxyW/sAeC2gBtD9DqmEF6SIlxEcGYz6qBIQI3cqFCIwf2oRe0NzI2MzDhU1MRMY2Jm5eaVcbgbs9FskcwRAIgK/gxq8JG3VBu7bBUbWyIKTDJu45Uhih7tJ9rkNROZCICIDtmUZbs6MH7gzDDkwaoBjyDie+Wj4iPxRAdNi93MHzBgSECF+MpCGkrUlz0cRYFSY2L7kF4FmaEPVu6yFcuLaRh9a9HMEQCIAuzau76nnUSb5sI/Bs8kZyOUXk9YJxTjofWvV+uLyzaAiB75JuK4hH5o5MNa9/naAQOozZz9DzLYFdONKP5XB49x4EhAynZSqQ0labfEdO3agAqUy9BAsTl4QNGYrJFaZX19M95RzBEAiBTt54PAUiGnCuAoGJHjOdl0eUSzrXbiFlRQvEDC2l6iQIgTWC9b9ghn0ovbizio4iYUuHevv+E0cA+GQ7/BcBiCI6BIQJ5Qi+ADdxrq9Uia+BOuikL4cmfbV3Qtlw0axDXRSbdr0cwRAIgZz+ye1itvCnJ+fVKCuwi0KtwMCh1/rrbOB6CStcTha0CIAg+u6Qt+U/9gPAMhQZTIqN20MBmD2c2Ch2WQ+CEtl63gSEC1gZiUzpFBDzFda/3hxWveGCNi3D5yLWdIMPOHs2Ck6lHMEQCIH4imB3NqRElkLmcaHiv1mHkAbhWCfZA69FEVjaosXO4AiBHZApH7znlfy8NrepJvNaCkOObhrUzqP/rbJAnBwxseIEhAjuio+1JWUEHQewt8E5NkB9GQlv6K1bEXo9Sms6QBehdRzBEAiBs929jqUf5LGjcEbsd59QO3j/vRAD79bmK8lyz1RwwggIgT+n4qkjhVFGUZedq2QiQI6eCkHqbsdBxFBpr6lPkl36BIQJO6orHKhIO/62c2IT5vHZLARq22wGH3H1Z3csE6SiVNEgwRQIhAIo/FRwwFYdI4eIbu6NwKulvle0aQ+LTkOS2da9z6jaFAiAZTMshd2XHszGGcBGmAD9ldpV3cixSV5y7RuYA8VxjMoEhApcDsu+5nFsAb6ZCFC7h4d4jGBFPT864rMSwjVyMF5/oRzBEAiAeG5tSkYXUo2Zvy1nJCStpQWaQe3rbY5xCpXAQR8plEgIgOrh2k8r83/ps1tTIAGOZHR815Jg5sejmtcQmMzMYuYyBIQKDugkpKWD0e7B9ss43WoxqHb+o0/kMWf0N/SF8szc7kUgwRQIhAIqoW1K5m0R16CcgW02v2vkDWoyJd1KdFU3EwNTKNHFzAiA29zlfAXj3OyOjSIAL9svGsZQvOMaIuTL5mDfsPybIaYEhA+3EqJd490Zp76UQKvvJO8p5CV3B82Zgh1WtcEn80k9QRzBEAiAeCF6n4xsy8EhP/GhuYPq4OC76Sn/uH1fJbMUEjvgdowIgWAfRjHGMJE/WJxMK/xHPQAdmLggPIduCO5Mph/7gDi6BIQOet0Hp05Q0HR+yKil57TVI63HbLfiXK2fEjtjKhKZuV0gwRQIhAC0zjcxqAx/+5zT9vb8+glMwSFEcKFAN0YBz/maTKdfkPUx2ZkBM7XY0yTQ7yHTbDd92mTR+VUcp4l+l22CJi5En8ax87Uz7cCxI0u5/M9T+eTE6uhpvHMZDVXKSkQF908pEnbSVF+jivm7wZvvU6pvlE04cZ6bIp+SAf5U6nHk1glwpidDe9R3RIt9B48jkSHagUdQ98UOXAml3PlWSwRnmhp+GvhcEYgZkmIxjAw803X+fhSRG1zLdMM/Y9aMa6eAfwoIxwhPncgZyhPxnQIpQ+WznfbaMC3pVi3JSwPKIKCK0thh1y8/7mtJcKgiGGnbap9UM5pnE8m8v427zRWZvTSr0723VSTMSnpPDJE2PIT+7fm79CwE0owSVu7IS5+2D2yQu+WQFQbthNnvvBvU5zvF8jD0hac2Oggdi5fDkRN5LRxnC4DiEfnO1zlfxVzF5DqTNhQA9BlYovpKRZs38j/9ykYA4KdAQT60yOmGzUVhCBLyQocyxM7/OZdWUlhSK9Sra8aNMQx+Nmwo5eB1nXMYNA5r4VCBzjVVFYh6RhzDrCiFjs84pLsmqNdzFnKf+QwQV4WUKtg4r8SHv7R+voXBcDTljHlzePsnXeX4+4Y7/MWAsoZ54gvwTAlFpNP1SS3mVdWwfjIqLauOd76jLGbty14+R3U3yM1pGw7YvUlBwYd4ojnljRIUkGDZJMbZOveyVnEvubChm3qijBKBI+i5A5sXlAFkjE1RcbL2pNjpKz5dXhihYi58/x3V1GuoAKsno84iESzqjoekGsSkbzOsr3B1XOrwvKJWDw8Ntb4VUdKGUFm/LAgYWdl9CbvvO7Bbux9RaTCxbdH20vmPN3e0Wqq4JcicyDL35me3FegOv3UGJbJ6tr5gsJQvryIZghyJr9RhC2eho4eusJcaiq0I3m9ZocsVEdmYcN4Y3scY7pzBZIVFCa7XRx8giC9+K/PIALCL8zIb7nEW/+FL2U+BVWumXOqlQjkJT+wLH5kBolJLqhvibSD37Ge0w+HNk7eKaXyRvKe/lziAteiWE2IYngcURsXtjlCchOqj/7vLdcJcr4SqRtToqKWhzZ3vfsk+9QW8Y2DNm4piLUhqouD3ger9NJGginzPnEo81dfDXgKOh9ZMeFCNRXrNTxGp2yb3ok1Xzp/P8eILQU+3i27x1SUY8iVDv2dXnamL3hUz5KuzRQkgZf6qX+yDA1yHE+VHHtccmzIZyP/ITGFuCD5s4l3mqLoipgqGOzLOlQIZ/Bik/HzKd5VaotkkAy7qzKcErudfxlT72/C3GL8H8h85njCHYjXnB+qMg8yjCZ3WVMP+UQhCuZoPLoe0GIp4G2UaXnkhueodCyh2e645XVfM3hhdSGRPquXJDOU+ZEa9f2LnXMww9fa1FtSZOMwem6KbvZKK0u3HPcKssCreGeXxhIVETvzHHlyrjAn73s4ARW8jdcZe/L4g+vxwLubeEU2OhWFd2fRub9dljNhNfDJtKhCVu5hFqEmRqTeH98ArWNga73O94RGli1no688E9bcYH/9Jf276z66w16Szs0APmko/Z1byP0xVU+5q8mhFwpDzkpAubWjskMRuqTnPm70qPSUFXrrsJmSTp27n6PdsACIufxe62VpXXpX5uXXBkO+bA87yrf/Fq1Q7MDnGT8uWiNIPMoJBkE7oF24gxEdpvqpmuQ4p23pQ24mdlXXluPqEft+9L9cxp1lrvwURXcmfJIWXzCVkaxfeXpgKOy0uEx34zhcWBFU6+tGpvUCq3/UFkCli9NVWsWovrgRIgnyu/m0ecpKwkcIekCdLtbTLonnNKk3hfjmtlcDggn3LdiKDMMsZxNQ4XjqT52lLBGq8YD88oxZ+M7AVguBeq7c9y36q1kX1ZAR1e7zWX+M9Mrm88dFLQGlwFE0JyxqKmfpZuYoDrzWFNsE8wseeve0WaoBqOXOa79Y7uwL8a5JmIb5M8sMl1VK1KH0CKInQWp0onGLoYVUBeR0HGbQwFj17O4vrMQDRRanQNGJsauDWDeab3/g5I6mbj/xlBxCccQ8l+vjeqeWMyd/DmkJnymU58PGVC3Pw7rHhLV/kXuQV2/RQ2qchVYKAo7C0PuEDDnSkyNMIeXnMwoVYe9Lt/UbHf6uWs9doZAiB6TNwScoXKrVIHIsE7dGYYraL2U0bqu9Bo3akIkbTIyoEhAun7VOyhalJZ97DMG3RKVi1U23oMukraMeBUk8BBBTG6RzBEAiBaCJUdUgn1VIS+NVoUgWEnm19xrTjlDERx97UX4/BuaAIgR+Qwau3vGymUPFSqjmCml8CsnSXfNahrcToCPFUq99yBIQN/Ji7I4Fz5qTLXR/6xW/0RaYF141qyXHwSkL0zBMnqWkcwRAIgRtLU27C0fplYSRfpdvCr7KeWIrz5JJSJkJRiwVmKC+MCIF95Fpd4VVxDlZQ3LwgzvlvvKmJTRD60lXlWnhhDaFTWgSEDmbfbsD36gOdobrhaEYEte9U1Al907kthbTzrtGPFwIRHMEQCIAH1RFLmXmqmbaRuLSBQG0RAsDGvCbysb3P/y5DU5ymxAiBS3xJaiOyteUbEmZsZQuSKy/AQRMFzSwW+E0kqIoswQYEhA2j56wX1g+jHSuYxwR8FIX3AzdRP889Bw9mlc/OrJA6GSDBFAiEAs5loYigCAGIlOljpi0aNJT7JdadOhRUbfCFRdFyQS+ACIFmpbPpNMM6Rft1HLk5q/tf8Of1lE+zuoKdqwQBeHWXAV86eNPbVPLTkhAR38VZSrwMP7wCyaAABAStYGwAAAAAAACIAIJxdgoVWMpu/290HfivJ6nh8wVsnvF86hhGHN//ULorIAQj9iAEFAEcwRAIgQ0i83/hBqCMhBxSbu1CmTFfZyZnhFusPxFJpNUqDt38CIELE2mAumSoBiaCGKJpTy/Rak0jFOQdq9/8gePPnlbksAUgwRQIhAKLiACb5vaaKOJb+cAaC0+Tec50f/lENw7Yh5iARxq6mAiBtH+5YIUKe4PEb7xDq37IIbcLPcclhjsHd3IErMn2qKwEAAAAAAAAAAAAAAAAAAQErWCEDfVDk2dUYRzWfBlGlnnEkzeYX6IE/l1McpOgx4W6UICatIQO4aJIBtXcWCs5cZWnA1eu4kjnwLdRhq9DnQ5cbAAAAAAAAIgAgnO/m4rgsFyMMjHJf1p14xzXIDjUJcOq0PEZHMEQCIAQvXZYZviCRfyQiMQZWP1zXOx5PRcFpfL+KjPv3GAStAiBuDPyfcCFPMf8hBp1HASnsEsGg7753gNXFInx9WkE8KQEiAgNS/FkIKLKSyeVR9Sg+KkK4hHgkoiJhsJLYZqiFmCNccEcwRAIgEqzI/znuxp07jK1yZMoHxq5GCO17TQbRGI1xRLtpFqoCIF6P76+SOZF85vi/1WJ+pVQ3LkMuqP9Bs3Ue4cGDMdTvASICAnVnZt44kuWTxyjZ6ouUmDVBGkfteVRNdcG+/MofA5aUSDBFAiEA1kMmjSNYNDYwABKOjeCOIXDgo0CYicGK8Wt5tZMkKHgCIGnW2ndoqKBEZT5Z5p9YGQYfG6tUkS3TqB1/vCcYguQ3AQEDBAEAAAABBakhA1L8WQgospLJ5VH1KD4qQriEeCSiImGwkthmqIWYI1xwrFGHZHapFMYWYiP2BmNoI/Lpsz7aJHUyTbobiKxrdqkUFv/c7FFep3Pq0YLvKl9tPs4+6JiIrGyTUodnUiECdWdm3jiS5ZPHKNnqi5SYNUEaR+15VE11wb78yh8DlpQhAj08EYZ/y87v5uK4LBcjDIxyX9adeMc1yA41CXDqtDxGUq8BNbJoAAEBK1gbAAAAAAAAIgAgojcWQ/3MIpoGMhKAwimEh5JuiP////////////////////////////////////////////////////////////////////////////////////////////////////////////////9g8HE8L8W259LvcgptIgICPTwRhn/Lzu/m4rgsFyMMjHJf1p14xzXIDjUJcOq0PEZIMEUCIQDFVwAeUeKBcwAKA/Mlwz08BOSWSZcpEtWIg/n33pYalwIgaOHS+CVrwEyXvbV4jAayT2CTI8pumcFq5SZ3JM09SoQBIgIDUvxZCCiyksnlUfUoPipCuIR4JKIiYbCS2GaohZgjXHBIMEUCIQDT0+35xxfc5uGAWoLMZ4cfS0O8X3gXq21k4z5NMiv3TQIgJAiYyX5cDyt2Gdnch0GV7CCqhPFUM6UKalkrYAxHgXMBIgICdWdm3jiS5ZPHKNnqi5SYNUEaR+15VE11wb78yh8DlpRIMEUCIQD96y7aYT8PtAQAAEgAIgYCLr+ali2zUlMVtaqZd82JbAfzEpHcUlbgk+EuChXGu72TDFJtvIcrMeoqIQIt00409C2vhaSFQOwZM5Jw9H7fyrm5dykpKfovmHX5eiGxYdo//0gEAAABBSvADQN27t0gc2J0/wEAhwIA+IUm7S9dgoVWMpu/290HfivJ6nh8wVsnvF86hhGHN//ULorIAQj9hgEFAEcwRAIgPKjnM+tKF2HwwOlYrfe/gX+ikz7OgyedD71FzE6BGwoCIF1uwiZsFC5zgyAcp91BHUNe08O9M85Lo1dPpF52CwMzAUcwREIgWPfqIg3ZHjJRb740DmpiVBNPYepEaJKNMyDBHH+cW6oCIGFBGWW6d6CXg+f+ZXoV/jZf9MPkIHtAeZbG9XUhsHdW/Iu8PZn0734BqyEDFVvw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").unwrap();

        let sign_msg = SignRequest { tx: spend_tx };
        process_sign_message(
            &test_framework.config,
            sign_msg,
            &test_framework.bitcoin_privkey,
        )
        .unwrap_err();

        let spend_tx = SpendTransaction::from_psbt_str("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").unwrap();
        let sign_msg = SignRequest { tx: spend_tx };
        process_sign_message(
            &test_framework.config,
            sign_msg,
            &test_framework.bitcoin_privkey,
        )
        .unwrap_err();
    }
}
