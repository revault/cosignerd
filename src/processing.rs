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
    // TODO: Cache it in the caller
    let secp = secp256k1::Secp256k1::new();
    let our_pubkey = BitcoinPubkey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, bitcoin_privkey),
    };
    let mut spend_tx = sign_msg.tx;
    let n_inputs = spend_tx.tx().input.len();

    // If it's finalized already, we won't be able to compute the sighash
    if spend_tx.is_finalized() {
        return Err(SignProcessingError::Garbage);
    }

    // Gather what signatures we have for these prevouts
    let mut signatures = Vec::with_capacity(n_inputs);
    for txin in spend_tx.tx().input.iter() {
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

    // If we had all the signatures for all these outpoints, send them if they are valid.
    if signatures.len() == n_inputs {
        for (i, sig) in signatures.into_iter().enumerate() {
            // Don't let them fool you!
            if spend_tx
                .add_signature(i, our_pubkey.key, sig, &secp)
                .is_err()
            {
                log::error!(
                    "Invalid signature. Got a request for a modified Spend: '{}'",
                    spend_tx
                );
                return Ok(null_signature());
            }
        }
        return Ok(SignResult { tx: Some(spend_tx) });
    }

    // If we already signed some of the outpoints, don't sign anything else!
    if !signatures.is_empty() {
        return Ok(null_signature());
    }

    // If we signed none of the input, append fresh signatures for each of them to the PSBT.
    for i in 0..spend_tx.psbt().inputs.len() {
        // FIXME: sighash cache upstream...
        let sighash = spend_tx
            .signature_hash(i, SigHashType::All)
            .map_err(SignProcessingError::InsanePsbtMissingInput)?;
        let sighash = secp256k1::Message::from_slice(&sighash).expect("Sighash is 32 bytes");

        let signature = secp.sign(&sighash, bitcoin_privkey);
        let res = spend_tx
            .add_signature(i, our_pubkey.key, signature, &secp)
            .expect("We must provide valid signatures");
        assert!(
            res.is_none(),
            "If there was a signature for our pubkey already and we didn't return \
             above, we have big problems.."
        );

        db_insert_signed_outpoint(
            &db_path,
            &spend_tx.tx().input[i].previous_output,
            &signature,
        )
        .map_err(SignProcessingError::Database)?;
    }

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
            tx.psbt()
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
            tx.psbt()
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

        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAF4CAAAAAcO01kMBcq/the17x8p0bq+eKhdtRZuQw3miILhNWCxbAAAAAAD9////AUwKeRDzWgAAIgAgDRpjEo1iQURQ3ysbrtcWS1IMlDFMpIsZ0bMYFsQtaocAAAAAAAEBK6CpeRDzWgAAIgAg7UCig+fTNnrs42UVVXSY7Mi8ZD1SsysCta1+pdRDp6kiAgLQftmhw7FLy0XwPPfI9E+exf4lCJ5BT5ggGKUwCkglAUcwRAIgERz3msqCYntoB4nQENCNTWC6F/UKCg0FBUIABT0tzdiTe3F+AiB1GjAgDknLOVPYP4V2N/L+tdAllL52uxLv0zNoeDuFIYEiAgIJDAqihbJGxZ6hX8z9lc+YUQ7s4XhbhNKYUG52kekBCEcwRAIgd1eyx+Y2WjMy0qUmONxwlzKOuEPX3PLDjZaF+NC9C8QCIHtaUrnHD0xWYy4NPVh2/irNpZLFZJGP1I9foSJC/g4hgSICAxp6dCg9pplDNXMj4QEjDlp9rdbuL1RHZN2xyJp6AB0SRzBEAiADXo90qBvZ0bru/CpnlYB/faG3v9/5bpxujHukgviixgIgc94+ByvMmnX63pyvXtZHuTQgD1xf7I6ucG/HWfOJ2duBIgIDN3aXvWnEAcR02WYLsisXo00eK3AO5m4W5CZdEAxEsh1HMEQCIHmY2+fYT7qcjkN/KADqszBNeS2krDznT1vaiA19H/H4AiA/XC1dLYmAaWeBByC5JPjyo4xuB53AKY1q4xPa0WfV84EiAgOJMvJtmyWvOdZ8VoitdqkUVksi+Q0QYLfM8yxMBbH14Q39bYqIrXapFKHgaUzAP/wngu025grBoVio6jgdiK12qRRoC2RwqqreXU6JwsGhnQ6+AolfuoitdqkUlB4snI31jcyvxvngGJaVOTUK0VGIrXapFKyiuLHEuv/RMuv7NY+rcHx6m4EeiK12qRSLief08BqREdJAmKB/Krjm1yT3WIitdqkUUYlwdtlB7Si4kuFH2aq0n48aK0+IrXapFC1AaSvBgT2FY/TH6iWdCrrZBBJliK12qRTUWUEa5Hg2ThovKof/XGyQKvA+ioitdqkUR+QU4dSiNcOJ9oldPaXIInzQwVqIrXapFMBptHlpXTVzShyiwtz05VcXz+UziK12qRSeg9xW4pqKOw0aw21ancOG4K11f4itdqkUWghZdWluueaA6EBvpncH8PopwKeIrXapFE8drZy4B6Of+q/jrl3v4yg8TgSpiK12qRRon+laoTnasOoBav2vrk4FIbFrPYitdqkUYV+bMC4QjdHv0YacswR00gUm2lGIrXapFJDw1vdnNympod7Ajg4bdwSkGa47iK12qRQ7fP21sV9w6Yh3EDI7peoV/GP9MoitdqkUNdZN7V5Y/xz3V6gJYG8mXytV8hiIrGchAiHcUhp1Kv7UMq9tlX6eUTkzg9F7rFapDrXKh1QLc0cxrSED97JGqKpWWIMSW/R65sBDuRxqPjP2gtTC6EgXeudrnC6tIQOzVSwbF8F8veHApNbev5XZMt6WJrdpAgrS2RMSk+JREa0hArX3Wddz3zRZfNzKU2ghlUMNQ64Q7DCBseCLO/EG0NUlrSECf+tBnjGwVAsv8ksyR6Golqxf1fPnJT8foMONX1NQaN6tIQNOSTvQ/PGYBf8hKVGx29pce8WwAQlKhBjyC58vGKO3SEgwRQIhAJc9bvJESInQ9WxDONHtJXAiIOJP4ctoG7joDST7atNSAiAbDSci2Nz8a6zly//jK3BIHBl6YeAvR6kzox1U9pB6hYEiAgJ5TKJVinelTsDbLOeptMSd0D1HkW+6dkXA0+iTT9yZSkgwRQIhAMPPRWc763eXOBeYxQrRGNhymuYBwpdtkXCEeoM81+mZAiBXTy9eWzpAhUa/cIPTS7RePMUCtAvqB9GW9PYbZ89tlYEiAgPA6ysLBFRkx7GWjn9kZf+KqtOHMdofKhjG0vBY+sJHS0cwRAIgWea2vUEez4J8y8PKJ662M6xOtomMSfFBcwpcrgtfNPsCIFJfWA1XuPK5yadfkD7VaJQheJ8uWwoC70mg/XE18lCSgSICAvmFBFXfzTB07AUVsq4sOIl4OxDaLojJ0Hh2GFh9e3lORzBEAiBJ5x3ifBR1gRuh+o3i2qB7brAAgl8XyXA3f9+/IJjXBQIgM5V0LAMmALpAJVb/Rop/lpNDFiCOxg47Np/q1A/NpueBIgIDVdi0XOor13Sbtuc4U2nn7QftqjwxA1klylgPQA6A3FBHMEQCIDD+Ppzo3/ou/7T+0TEE77ZmO/u4YGF0Z8qgP1M0q7SwAiAC04HksRO/gwBzCgtWhTFazFsbDvfpj05NsUnxYcSskoEiAgKYA76bTKszGSTnqDE7WBF9GQVUJAoAugdwrEvVCfc/VUcwRAIgIDu6dMT51vAwGLa9RlZQa26p1mhtHUraDQqy6w9vpfACIFkukCa+KCzYQ1gA5S8BO6w1FVuENiBDDu7J4Qywr4BUgSICA1VscIdwSVXYc+voCoPH/dl8+TKsbccREYWlnLYk8E1YRzBEAiAD2uPF6KPPQtqynxNj5r8zt43KdPLrzwSEBM4ja4pQigIgZ56mOhMONoXjz5Q8eFAc9uawQaUm9RDvvnUipv2Y4iWBIgICFGMoaBylqJXCqzZ6ybiK0stP1Awj99XV3g3Lj2ddTFlHMEQCIBKMb5OInhC5jJ9rF/faTmFDXqj9BKCNZTza0O/0O7sgAiBC76CbEGsh+R1TT2C8t2hPkRK03gGN8egxYdpZorxxOIEiAgILOIA4N4Zu/5oNjEzNj/cKDqKBH7rtUmDEwcTCLzviXkcwRAIgKzG/sh2XTh2nzrAp1MCqMmuKQnn/kUOvL32IjVXBIcICIHTsVgNlVArYnvvNE81QmxY363+SlrSZzSbSJ8ZK6UqvgSICAlif5hm9HYvcEDi6JwOuc+rYWOdHJz0TV6wFgNXEUQ9fRzBEAiAhhHheoS4zhTFboB8u98HD0CtDsYzf8elWpYUCD23WSgIgIcob5qrPaFqMHsO0tETnxiZ3PkjTUfbeRiHnWshcO+6BIgICuWUkaiGefe3ishGrxyvaY/+EAdhYkaJ9xhqTISHQl2BHMEQCIDomu0Oj2U5IfJlYYJfFOSURzd4cj7zo9l/HqUZELg7sAiBQgZLyODcG7j4zcu8W1mKpNDqtZBSvEtpCHe8LU8+M2IEiAgKneSGE6umX1oa4Kg6mFNrb0kfg8STl38OOzBg/rs/2akcwRAIgOpVFb6rPALVKdSWW2WKPTVY0TUf4BpQFD35rxpBm/u8CIBxXzkNfQCHPGq8gEEEReLAfwQtnn85vgbZYkefRm7M0gSICAlWJb8iEyUADVCF5g018XgEFVplNYarAUlqKXUA2P2B0SDBFAiEAkjAeQW4YU+Qpwv3M7kL30emC9NFlzDEu6rfnyVFbKt4CIAwl2JXb2vP7vwPuHJWpHn25sVuKIKNJMVuDhqZ2Q9pdgSICA79dF+IUtCFpZ1ugWT5AcvAVn1iLf6iEkTwrX0WzDLl1SDBFAiEAhZmCzPwacB1GdvxCwrt7sE8Ss9vC9h+c0vKTbcAyXLACICArDHE32jCHj48ndpp7DtD8YPZGIrl55Xhas/7hl+r9gSICAlvAy/eiofSkrasRA/UgGo1yogx5xZafn5NtgLqFgld5SDBFAiEA/1I2j9ksqyyqPpSvkSJHXMTBL2aHbmSqM7ASy14IqucCIAXZ4LsjGYnoTAPclT9hGEOHJeBZeqtn9obrUbk6izYlgSICAuOeLRhBVYUpVcA2jo9NPzt5fD7SOex8hjprN90N2xt8RzBEAiBIPXJjDbFH/5lXnMFSNLDLOb83XNkGhttYgtZqn/TJAwIgQvS08LIcxtxqWxfkYXe25TSZFjIcjUQXh+r3ZZ/MXx6BIgIDCgLrLvgwoWRLRvgrrR73jqqYrDCR9gkjostjBnFdnpBHMEQCID2Q/H8L4l3YhEvJ3YdLn0z2YCALlrE6udFRDqdCCUIoAiB+p7hdTFZbfSKJzaoQ5lWkTdH+7zgvruwvXfxzkImfJIEiAgPPq6Y3f0iAsisM+dytqlQj0r2osSbjZNRyC7RLbAA6ck5Ge0BhcKcCIDwgUeg2RZjAhDR/eHdBQ1WhdFNTxA+E7ereMrkmaSaagSICA0ZwzghKCjPOSYX26sdqAEQV560t5BIsj3iT7CJWglfERzBEAiAmG0J8OmUieUvFyi/CieMQNrbR8up4qoRLp2yOqpF+yAIgM8olNj1BDf1OgH9nQI84haOtUyGU5qnJLUFcRsdsHf+BIgIDQ8gTj11dp+xTkPjJKGCbJUsb8AM2FOPKSdW600QjSNlIMEUCIQCgsBoAi6CeFWx2bTiPpFStua4Rp/EzQvXGdGsmKbGScwIgU0JaU/s1cDfhYWmH3U1ptCv40XSnZWbAs96ekppOGzqBIgICacZdn5UEkmM0I9N3teP7jNO5Z0YzCnUyowpwvrKOluVIMEUCIQCnUVgBrXZRR5ETt8bXseLCSDbHxqw9qOtImEhFLqzmvwIgA6NFHZk1ZcxfF6NVbM3Zf6+yH6z6xwfFh/1GrWhHhFOBIgICYqboBg66GK2UQZe+d+3fQ5v70trHE320BP5dHMoEg+dHMEQCIEMp2bpMrVmyYT7DJKUPVPv1wUvogHppo8mTPNUcoyIBAiA9H0c4odO1+Upz4C+64z4kjV1qnzqiuUSJgV5JVAe6OYEiAgN3KorN150loLKd2fDdtVOsnB8Y3SJELheEr9TJaCLm7UgwRQJeqy+csD6Q7S2tIQKkmQAl17/7JtCNqyNzQrpMBJ6BvuGa3FIjaj3rLdAKAa0hAn6azfDCXr3GgapED+XgA8DZaotxru3xWvQLHoZKiZuZrSEC22BSByFyTMj+o7pUPWeWyCQTBeyf6+3zDzxaRVbUN5atIQLxfznWiM8dm+c+wlTrKE6qoMj39PmxKXSwF8Rx73YWe60hAkww/bDWDZFeNPUMIEpBwaMvrAtM9cdV4aN/rPKI/zltrSECKhuPwa8K2MnTQnPZws1Mh87xYOSDEJHcBhgfYR6VVNCtIQNpUdfjSxfxjgriHZz4FSNZ3qzee4mv9ZZ9OT++cvxgvq0hAzIQGPnN3PIVJu7QrQBgyeiagxq2KrKl8mGgzdxBUfdkrSED5gyZ+Eut7bDnPP/ds0a8Uatm21aZfPO7a0OouXhi2R+tIQKir0/vL2zesiEVgEcf+lvL5lvw5ghBY8MBUSzMHuEimq0hAwQ4Y7Q5hTGO8WWmG5DwU3quVMV4gSGljvFoMUSiuRJOrSECaHn/ssODn6S/0kSZaVpf4jHnq8qWkBGNlQjYBnBKngytIQPqvMklgHtcsmVjjkuq5/84QY897V/ZmaS2XkhQLbUtRq0hAv1pTix+9bFSAZa2LSempxyMsqm50pzUaMbWYrou4pBYrSECM9cem6Wi56x/ODOZzZH7dAv5d/NoS3ep3T9dk4+0oIStIQPXVCEROBJ4vzywHjPyCggI2+ZcL3utXLpa2BXSrjJh1a0hAnjWrVN8wQBWHKyqseZsKjyT1KbADbK/dU3ZtQvtGRfUrSED2EWRtp34hd38+1ZSPlfrF+wxQ0OjkKS/SRkKnTq6H3CtIQIp4HGlzJfsJ5Qxs2vbhNkPAy2IVLwIuFJ8KOQ3LB7I160hA2tPdrY27kCZqiqyuA1ThwdfN3l2IFKClcD4MQ45Vc84rSECGNNyAwuQVTdKQEkUkpiXdjJ4FN8N+TbIkm6M4FjI4fetIQN9UOTZ1RhHNZ8GUaWecSTN5hfogT+XUxyk6DHhbpQgJq0hA7hokgG1dxYKzlxlacDV67iSOfAt1GGr0OdDl+yDRI1CrSEDb3sJZORbdqHhqHnh8b7t7J2jSB0yoYthUWYgTeGQ7nitIQO8AZDTE5KlwzK6IwMDOjOpjdYuo+vwAizOs3gK6m6tkq0hA9w/hcKq68t5hS9OH+DIsSlxNiSGmGsQ2puFtFiQii4wrSEDwF30RTyyojKF5UyTeGyvwMZfrp/FmLRHUp6Sb5+NCHatIQLjBRgOu1xH8nDPnL/B/CHt57PEyXM9CchgpmWOTt92xa0hAxgy/q2iBtL+SRsn1rDJtYHUBEATx727VIg5ILFZssfFrSECzHJQbfj19kL12QA7HGZ/iViptYv8Aaqz09S1M+JwA6+tIQPdnNCs1y0hypHH9EX7c54QAssqe7WFkqe67pD62qWPWq0hA+/FJztumB1YqGpbglMG9nnGo5/fdn98/C7BFemlsvHLrQMu+ACyaAABAStYGwAAAAAAACIAIPOMA4RMJOeclnzjINo6G30m7+vimIDxrsvp0GD8xaS/AQj91BUtSDBFAiEA/lyHJ+XzthBoDCECeNatU3zBAFYcrKqx5mwqPJPUpsANsr91Tdm1C+0ZF9StIQPYRZG2nfiF3fz7VlI+V+sX7DFDQ6OQpL9JSeUU5Hh9FV1HoOsEWA0CIH4t9JJ6B735HoYffA/nw9cjxyt8XtnFsA962PJDGbsZAUcwRAIgRm4yV+DN+BXpdVZDoWU/n4mNC51LVSwfSAXzQPbhC2YCIDmQPddgtjGf9m/00KPfQjHi6bHcwhgCdpspqWjq6iB4AUgwRQIhAOLUv0yg4JBul5CIjqIVAQql9tLQDVDQFDmr3NpIgdofAiB4DE/EZzrvS8RM/U0yDjAZSiRxwa4rfgIrbzAyWVWUIgFIMEUCIQCHffimYdNY8C6hw9M53XHmEmMv1MCRIT1YGf5cTiwAfgIgEBgwu5EODSFeEVrKlIofgUXtkMIOC6m3/7FpMevlRNABSDBFAiEA9rf+QXLsK08JU4uMiY8HTzITUhj4+et2bexzIrnHhp0CIAv8t+vGPnPq5goz+idnHx8zn242wWgHITaRdhMB+EEPAUcwRAIgPsKCOdSMDIpeSmwS6y2aBEdSr8qjeoiVR9r6clX8Mz8CIGe5+u452Z4Nr9W0jO0VfKgrJGQyz/2hpcbII6iip7rRAUgwRQIhANBioLoIpOQIWN7sdtfndzf4vRvr8G86vum7CubLtbeWAiBRc6c8HUL3tQkS3n9WiSKXCaMyapAJFNKRvl8Av9Ui/gFHRQIhAId9+KZh01jwLqHD0zndceYSYy/UwJEhPVgZ/lxOLAB+AiAQGDC7kQ4NIV4RWsqUih+BRe2Qwg4Lqbf/satpXo8yU9wwholW2SKd5po1LvG3OVP0vYikAUgwRQIhAPcow9qu3Ve4TVcqSM4XzOP343yowpsn55nHobATLFCrAiAX6NdtpBr2bgHKQCUzitP4QKfeuO8Crp4ZAjg6UrkmKwFHMEQCIBW2n08JBJ6gPapNrv/jMnOJWo+APuUbixZJWemNpAMoAiAtawolBNCYAKbfOwXVpTp7L8vAV1uRcEsBxKSVi7iTvgFIMEUCIQC1Hn8+IfPbEBPC9N9fwiYhRQHR+W3SK76IaWDDiKu4zgIgGrHiLFR1mAU8KsM1hfzcL4bpSmFFApQIOqAJ+Pp6wdYBSDBFAiEA8zBCQsfeacXVwYRjYGTOXLe6gAmL9nHPHHNH6h2NNNECIF3kt+C/4Cfk/SWfzPse7P4V7y30xksiSk42gVHsvdEoAUgwRQIhALwM6mCNtMOSaDsETsiO0gInP/A+B+zjk5sp8WM06DdDAiBvRuhFwvMTnE56mJTvLZowxUd/ZHKFYqVVVJLTUOxVywFIMEUCIQDa29o+ywPoZaL3vGs9lvbL/voLSj8BS74ajyb8kj+lXwIgS5GfJcMlICxi6jlQnx22GpILNKadyIrdS1qxSdoZgH0BSDBFAiEAwuTWQtm7Bhg4D3CGTUvHgwfBkK/liIEx2XmJbSbtx/ACIACLDxfS+dVvr7paIKm+UNgE/uD++OWR08/hB9Q2dgPQAUcwRAIgYscIhdgc2QoiPl2k8j7mJwyLLN2DGd5Qm80Ib1hTpdUCIH5fi6Ymh0MtiCtEbDsg4PALWwaOIovbYh8srwXB1SeIAUcwRAIgMKILVIPEgjOtUoR8yfObDsMkWz7e2nDjFEH01x+3gakCIBsEuhNxLXJMIRU3G7J1AdSYZOb7deh3RvNc/UnZLWlXAUgwRQIhAPWsp7lxN7Bs+X8MXaDKdzF2OErCgtjKNvNTQi6x4kK0AiA0XA/55HzleXyFE1DhHZzbJ/vp080S6h6oI7ckdCG/7gFHMEQCIGTDUUcPgjbQo9OovcB45Q2oak64tpLl6YAbVBW+1olvAiB/WJKRtd/Ef4CGK0jIFDGZUhQSi51YVoaDqxDRm1vAvgFIMEUCIQDagCS+ht4B1yQtrcTOVfg9ui/1c9bK5ThshcRWKwApugIgFaiqlm1m0D7tb5DmwhchDo3BVtybhjN2jqRmTzgn9FIBSDBFAiEA5FL9fp2WDi9s90DAXaxH20glUjie6KqQlshGQA6H6x0CIBBstA6X5Ed4dAVl5BpEmIEMuDEzjn4qwiU5qVYNiZUNAUgwRQIhAOgz3Pyse5DAn7Xk+9OMi2uKOVkZC7UDaAk1wGDoHZAWAiAFfT97uKNC4QB+5nhsxedZpIsfAZBglkQgH/a5WTbimQFIMEUCIQCISgWpOtLfqTqbgQYwbiw4kxdK+YjUfeiIVuvYDaOTBAIgLYX4Hlz7fPe13HtDc89SoOSm30cvKS36DJSDkbIZ3nEBRzBEAiBx2enSE1g5omalV8PudeAW+YuLsgFgVDjl/09KxzFYGgIgUvIqxYqZDn5GM3UCBn/ceNpqTXAT1RPBMarREzKzV88BSDBFAiEAuXWD2qpweTkYzNs91nxWiK12qRRWSyL5DRBgt8zzLEwFsfXhDf1tioitdqkUoeBpTMA//CeC7TbmCsGhWKjqOB2IrXapFGgLZHCqqt5dTonCwaGdDr4CiV+6iK12qRSUHiycjfWNzK/G+eAYlpU5NQrRUYitdqkUrKK4scS6/9Ey6/s1j6twfHqbgR6IrXapFIuJ5/TwGpER0kCYoH8quObXJPdYiK12qRRRiXB22UHtKLiS4UfZqrSfjxorT4itdqkULUBpK8GBPYVj9MfqJZ0KutkEEmWIrXapFNRZQRrkeDZOGi8qh/9cbJAq8D6KiK12qRRH5BTh1KI1w4n2iV09pcgifNDBWoitdqkUwGm0eWldNXNKHKLC3PTlVxfP5TOIrXapFJ6D3Fbimoo7DRrDbVqdw4bgrXV/iK12qRRaCFl1aW655oDoQG+mdwfw+inAp4itdqkUTx2tnLgHo5/6r+OuXe/jKDxOBKmIrXapFGif6VqhOdqw6gFq/a+uTgUhsWs9iK12qRRhX5swLhCN0e/RhpyzBHTSBSbaUYitdqkUkPDW92c3Kamh3sCODht3BKQZrjuIrXapFDt8/bWxX3DpiHcQMjul6hX8Y/0yiK12qRQ11k3tXlj/HPdXqAlgbyZfK1XyGIisZyECIdxSGnUq/tQyr22Vfp5ROTOD0XusVqkOtcqHVAtzRzGtIQP3skaoqlZYgxJb9HrmwEO5HGo+M/aC1MLoSBd652ucLq0hA7NVLBsXwXy94cCk1t6/ldky3pYmt2kCCtLZExKT4lERrSECtfdZ13PfNFl83MpTaCGVQw1DrhDsMIGx4Is78QbQ1SWtIQJ/60GeMbBUCy/ySzJHoaiWrF/V8+clPx+gw41fU1Bo3q0hA05JO9D88ZgF/yEpUbHb2lx7xbABCUqEXqsvnLA+kO0trSECpJkAJde/+ybQjasjc0K6TASegb7hmtxSI2o96y3QCgGtIQJ+ms3wwl69xoGqRA/l4APA2WqLca7t8Vr0Cx6GSombma0hAttgUgchckzI/qO6VD1nlsgkEwXsn+vt8w88WkVW1DeWrSEC8X851ojPHZvnPsJU6yhOqqDI9/T5sSl0sJfEce92FnutIQJMMP2w1g2RXjT1DCBKQcGjL6wLTPXHVeGjf6zyiP85ba0hAiobj8GvCtjJ00Jz2cLNTIfO8WDkgxCR3AYYH2EelVTQrSEDaVHX40sX8Y4K4h2c+BUjWd6s3nuJr/WWfTk/vnL8YL6tIQMyEBj5zdzyFSbu0K0AYMnomoMatiqypfJhoM3cQVH3ZK0hA+YMmfhLre2w5zz/3bNGvFGrZttWmXzzu2tDqLl4YtkfrSECoq9P7y9s3rIhFYBHH/pby+Zb8OYIQWPDAVEszB7hIpqtIQMEOGO0OYUxjvFl5huQ8FN6rlTFeIEhpY7xaDFEorkSTq0hAmh5/7LDg5+kv9JEmWlaX+Ix56vKlpARjZUI2AZwSp4MrSG86gPJJYB7XLJlY45Lquf/OEGPPe1f2Zmktl5IUC21LUatIQL9aU4sfvWxUgGWti0npqccjLKpudKc1GjG1mK6LuKQWK0hAjPXHpulouesfzgzmc2R+3QL+XfzaEt3qd0/XZOPtKABrSECfprN9MJevcaBqkQP5eADwNlqi3Gu7fFa9AsehkqJm5mtIQLbYFIHIXJMyP6julQ9Z5bIJBMF7J/r7fMPPFpFVtQ3lq0hAvF/OdaIzx2b5z7CVOsoTqqgyPf0+bEpdLAXxHHvdhZ7rSECTDD9sNYNkV409QwgSkHBoy+sC0z1x1Xho3+s8oj/OW2tIQIqG4/BrwrYydNCc9nCzUyHzvFg5IMQkdwGGB9hHpVU0K0hA2lR1+NLF/GOCuIdnPgVI1nerN57ia/1ln05P75y/GC+rSEDMhAY+c3c8hUm7tCtAGDJ6JqDGrYqsqXyYaDN3EFR92StIQPmDJn4S63tsOc8/92zRrxRq2bbVpl887trQ6i5eGLZH60hAqKvT+8vbN6yIRWARx/6W8vmW/DmCEFjwwFRLMwe4SKarSEDBDhjtDmFMY7xZeYbkPBTeq5UxXiBIaWO8WgxRKK5Ek6tIQJoef+yw4OfpL/SRJlpWl/iMeerypaQEY2VCNgGcEqeDK0hA+q8ySWAe1yyZWOOS6rn/zhBjz3tX9mZpLZeSFAttS1GrSEC/WlOLH71sVIBlrYtJ6anHIyyqbnSnNRoxtZiui7ikFitIQIz1x6bpaLnrH84M5nNkft0C/l382hLd6ndP12Tj7SghK0hA9dUIRE4Eni/PLAeM/IKCAjb5lwve61culrYFdKuMmHVrSECeNatU3zBAFYcrKqx5mwqPJPUpsANsr91Tdm1C+0ZF9StIQPYRZG2nfiF3fz7VlI+V+sX7DFDQ6OQpL9JGQqdOrofcK0hAingcaXMl+wnlDGza9uE2Q8DLYhUvAi4Unwo5DcsHsjXrSEDa092tjbuQJmqKrK4DVOHB183eXYgUoKVwPgxDjlVzzitIQIY03IDC5BVN0pASRSSmJd2MngU3w35NsiSbozgWMjh960hA31Q5NnVGEc1nwZRpZ5xJM3mF+iBP5dTHKToMeFulCAmrSEDuGiSAbV3FgrOXGVpwNXruJI58C3UYavQ50OX7INEjUKtIQNvewlk5Ft2oeGoeeHxvu3snaOLHTJRoWFIZiBN4ZDueK0hA7wBkNMTkqXDMrojAwM6M6mN1i6j6/ACLM6zeArqbq2SrSED3D+Fwqrry3mFL04f4MixKXE2JIaYaxDam4W0WJCKLjCtIQPAXfRFPLKiMoXlTJN4bK/Axl+un8WYtEdSnpJvn40Idq0hAuMFGA67XEfycM+cv8H8Ie3ns8TJcz0JyGCmZY5O33bFrSEDGDL+raIG0v5JGyfWsMm1gdQEQBPHvbtUiDkgsVmyx8WtIQLMclBt+PX2QvXZADscZn+JWKm1i/wBqrPT1LUz4nADr60hA92c0KzXLSHKkcf0RftznhACyyp7tYWSp7rukPrapY9arSED78UnO26YHVioaluCUwb2ecajn992f3z8LsEV6aWy8cutAy74ALJoAAEBK1gbAAAAAAAAIgAg84wDhEwk55yWfOMg2jobfSbv6+KYgPGuy+nQYPzFpL8BCP3RFS1HMEQCIDn2LlWe2jg1kHNvLWazwwsRmPiNKMnS5yWrAF+QC8C2AiBEtEpNt2PsDSYVBEUiU5PtQXSwsBAaYcJf6QmavH3PYQFIMEUCIQDYopiLYMxnQnmwSQx5ZVLgbMpSMiSFrSAh6A9CIn+LhQIgIDvoKdSPW+dE8/cOMNCBvgAQ0gcaOZVtgFZGqb4QMV8BRzBEAiACemmsvZMLr6fA24eJmlfy3Sl3Vd0LdZGWRPoDuH3tfAIgJ2APUreJZdYy7xlVmS+f65xjK1kHoo/X+EHeJMlvmr0BRzBEAiBO4PEDgsqnTOENgd0WY3GOYROW3IkgJO8p9MjbgwahFgIgBjmJeqJoHt6g+qEovPY+OV22MbEVFwi1LoWhqvqfxHQBRzBEAiBmzMXcyMfq1d6ZArPPjTST7M02km6ZgiztIxEDQ/bW/gIgcFv6hvHwVZa/HfFGp4iPZaIp7y4svumoUVCIsBnXDvUBRzBEAiA63P7zWYtyOpqgOsVLqfd8W6Pf17hI9MXeQS6FZ6xHGwIgDYwmDTqBBVfBz7h1PRyvT9rt/lVQ4dZ3HquiGbAj7hQBSDBFAiEAwPTp2p4F0s5inXICt6YneVYgb0ZkFc+nUNOWiLLuMGoCIHFy5MIO9loDir4NHd6H3iOISM7/axdLVYKFq1HHf/Pr3QFHMEQCID2iKSVgfvXEC1oSl4YxtVROHWJHnSY+12bOBFL0q0AoAiB7fl7oRSGUqdPUkfRyjUEGPdSTONz4uQWh+jXvuoBHswFHMEQCIDbh9pkCdt7KCeZrI0Tzz1+u3EnlFOR4fRVdR6DrBFgNAiB+LfSSege9+R6GH3wP58PXI8crfF7ZxbAPetjyQxm7GQFHMEQCIEZuMlfgzfgV6XVWQ6FlP5+JjQudS1UsH0gF80D24QtmAiA5kD3XYLYxn/Zv9NCj30Ix4umx3MIYAnabKalo6uogeAFIMEUCIQDi1L9MoOCQbpeQiI6iFQEKpfbS0A1Q0BQ5q9zaSIHaHwIgeAxPxGc670vETP1NMg4wGUokccGuK34CK28wMllVlCIBSDBFAiEAh334pmHTWPAuocPTOd1x5hJjL9TAkSE9WBn+XE4sAH4CIBAYMLuRDg0hXhFaypSKH4FF7ZDCDgupt/+xaTHr5UTQAUgwRQIhAPa3/kFy7CtPCVOLjImPB08yE1IY+Pnu0K0AYMnomoMatiqypfJhoM3cQVH3ZK0hA+YMmfhLre2w5zz/3bNGvFGrZttWmXzzu2tDqLl4YtkfrSECoq9P7y9s3rIhFYBHH/pby+Zb8OYIQWPDAVEszB7hIpqtIQMEOGO0OYUxjvFl5huQ8FN6rlTFeIEhpY7xaDFEorkSTq0hAmh5/7LDg5+kv9JEmWlaX+Ix56vKlpARjZUI2AZwSp4MrSED6rzJJYB7XLJlY45Lquf/OEGPPe1f2Zmktl5IUC21LUatIQL9aU4sfvWxUgGWti0npqccjLKpudKc1GjG1mK6LuKQWK0hAjPXHpulouesfzgzmc2R+3QL+XfzaEt3qd0/XZOPtKCErSED11QhETgSeL88sB4z8goICNvmXC97rVy6WtgV0q4yYdWtIQJ41q1TfMEAVhysqrHmbCo8k9SmwA2yv3VN2bUL7RkX1K0hA9hFkbad+IXd/PtWUj5X6xfsMUNDo5Ckv0kZCp06uh9wrSECKeBxpcyX7CeUMbNr24TZDwMtiFS8CLhSfCjkNyweyNetIQNrT3a2Nu5AmaoqsrgNU4cHXzd5diBSgpXA+DEOOVXPOK0hAhjTcgMLkFU3SkBJFJKYl3YyeBTfDfnINpJujOBYyOH3rSEDfVDk2dUYRzWfBlGlnnEkzeYX6IE/l1McpOgx4W6UICatIQO4aJIBtXcWCs5cZWnA1eu4kjnwLdRhq9DnQ5fsg0SNQq0hA297CWTkW3ah4ah54fG+7eydo0gdMqGLYVFmIE3hkO54rSEDvAGQ0xOSpcMyuiMDAzozqY3WLqPr8AIszrN4CupurZKtIQPcP4XCquvLeYUvTh/gyLEpcTYkhphrENqbhbRYkIouMK0hA8Bd9EU8sqIyheVMk3hsr8DGX66fxZi0R1Kekm+fjQh2rSEC4wUYDrtcR/Jwz5y/wfwh7eezxMlzPQnIYKZljk7fdsWtIQMYMv6togbS/kkbJ9awybWB1ARAE8e9u1SIOSCxWbLHxa0hAsxyUG349fZC9dkAOxxmf4lYqbWL/AGqs9PUtTPicAOvrSED3ZzQrNctIcqRx/RF+3OeEALLKnu1hZKnuu6Q+tqlj1qtIQPvxSc7bpgdWKhqW4JTBvZ5xqOf33Z/fPwuwRXppbLxy60DLvgAsmgAAQErWBsAAAAAAAAiACDzjAOETCTnnJZ84yDaOht9Ju/r4piA8a7L6dBg/MWkvwEI/dEVLUcwRAIgOfYuVZ7aODWQc28tZrPDCxGY+I0oydLnJasAX5ALwLYCIES0Sk23Y+wNJhUERSJTk+1BdLCwEBphwl/pCZq8fc9hAUgwRQIhANiimItgzGdCebBJDHllUuBsylIyJIWtICHoD0Iif4uFAiAgO+gp1I9b50Tz9w4w0IG+ABDSBxo5lW2AVkapvhAxXwFHMEQCIAJ6aay9kwuvp8Dbh4maV/LdKXdV3Qt1kZZE+gO4fe18AiAnYA9St4ll1jLvGVWZL5/rnGMrWQeij9f4Qd4kyW+avQFHMEQCIE7g8QOCyqdM4Q2B3RZjcY5hE5bciSAk7yn0yNuDBqEWAiAGOYl6omge3qD6oSi89j45XbYxsRUXCLUuhaGq+p/EdAFHMEQCIGbMxdzIx+rV3pkCs8+NNJPszTaSbpmCLO0jEQND9tb+AiBwW/qG8fBVlr8d8UaniI9loinvLiy+6ahRUIiwGdcO9QFHMEQCIDrc/vNZi3I6mqA6xUup93xbo9/XuEj0xd5BLoVnrEcbAiANjCYNOoEFV8HPuHU9HK9P2u3+VVDh1nceq6IZsCPuFAFIMEUCIQDA9OnangXSzmKdcgK3pid5ViBvRmQVz6dQ05aIsu4wagIgcuTCDvZaA4q+DR3eeSHcf0jO/2sXS1WChatRx3/z690BRzBEAiA9oiklYH71xAtaEpeGMbVUTh1iR50mPtdmzgRS9KtAKAIge35e6EUhlKnT1JH0co1BBj3Ukzjc+LkFofo177qAR7MBRzBEAiA24faZAnbeygnmayNE889frtxJ5RTkeH0VXUeg6wRYDQIgfi30knoHvfkehh98D+fD1yPHK3xe2XBzYnT/AQBeAgAAAAGJ3Co3vVvP7P/y1gKAjXbhDva8N5YzCp2P/nS752HugQAAAAAAAAAP/wHFsA962PJDGbsZAUcwRAIgRm4yV+DN+BXpdVZDoWU/n4mNC51LVSwfSAXzQPbhC2YCIDmQPddgtjGf9m/00KPfQjHi6bHc63Zt7HMiuceGnQIgC/y368Y+c+rmCjP6J2cfHzOfbjbBaAchNpF2EwH4QQ8BRzBEAiA+woI51IwMil5KbBLrLZoER1KvyqN6iJVH2vpyVfwzPwIgZ7n67jnZng2v1bSM7RV8qCskZDLP/aGlxsgjcHNidP8BAF4CAAAAASCuVMX0KpgDq17uluS4CaIcydpLflp+d9VB200M3uqRAAAAAAD9////AejKAgAAAAAAIgAg1WjP3wLFEiDPmTtWVZ/RenTsw9CE0N0aOnUfNurrnV4AAAAAIEome2pYNogoeeQcfE438MCgAoD6gxB1EjZmdvyRxrFwAAABAStADQMAAAAAACIAIAfaftBLtILi2rNBL5SGQ4NS4b2VlakYHG3ozyZbUn/nIgICyhi0aitHivtM51Ng74xOo5SIfAKA4geXb3q9yY1kdV1HMEQCIEra0r8i5cGkAmQ55c0euM2bZTFhw8A8jhhnwUM3XR07AiA5I/8GQu1Y11fQqaLbsplRQONV/6m+aSKqnOrmdTSZNIEiAgMqV2WwOtQ0GhW7AyYCZeXWpYpmEfzOLlnRv05LVn+MhEgwRQIhANcnQS8DzvFBNsHpEE68y9w+gpQ3YnsfHDFLr4aplsjCAiAdzxl/eSamqMzLstskqfiPT9AriG92a37NW9C2RqXCZIEBAwSBAAAAAQWqIQKztqYL1Lno92QcJGyg1RKOB+7oD3nsqV/nzX3q9BC39qxRh2R2qRTCJGPr2vAnCDADtM/+jYwCfGQnjo+IrGt2qRTqV9oAiEdQqkF1BKuyu+CFenv8GYisbJNSh2dSIQPWm12Ya82+ipu0tJFVoSLeOoTExWKob4R++AbgJJLGqCECT1goZK0gtAfewwbMy+x6xlULEHAiIX9Gv8CTkBvcMKFSrwKcEbJoAAEBR1IhAsoYtGorR4r7TOdTYO+MTqOUiHwCgOIHl296vcmNZHVdIQMqV2WwOtQ0GhW7AyYCZeXWpYpmEfzOLlnRv05LVn+MhFKuAGLqOVCfHbYakgs0pp3Iit1LWrFJ2hmAfQFIMEUCIQDC5NZC2bsGGDgPcIZNS8eDB8GQr+WIgTHZeYltJu3H8AIgAIsPF9L51W+vulogqb5Q2AT+4P745ZHTz+EH1DZ2A9ABRzBEAiBixwiF2BzZCiI+XaTyPuYnDIss3YMZ3lCbzQhvWFOl1QIgfl+LpiaHQy2IK0RsOyDg8AtbBo4ii9tiHyyvBcHVJ4gBRzBEAiAwogtUg8SCM61ShHzJ85sOwyRbPt7acOMUQfTXH7eBqQIgGwS6E3EtckwhFTcbsnUB1Jhk5vt16HezQS+UhkODUuG9lZWpGBxt6M8mW1J/5yICAsoYtGorR4r7TOdTYO+MTqOUiHwCgOIHl296vcmNZHVdRzACIQDXJ0EvA87xQTbB6RBOvMvcPoKUN2J7HxwxS6+GqZbIwgIgHc8Zf3kmpqjMy7LbJKn4j0/QK4jvdmt+zVvQtkalwmSBAQMEgQAAAAEFqiECs7amC9S56PdkHCRsoNUSjgfu6A957Klf58196vQQt/asUYdkdqkUwiTr2vAnCDADtM/+jYwCfGQnjo+IrGt2qRTqV9oAiEdQqkF1BKuyu+CFenv8GYisbJNSh2dSIQPWm12Ya82+ipu0tJFVoSLeOoTExUbzXP1J2S1pVwFIMEUCIQD1rKe5cTewbPl/DF2gyncxdjhKwoLYyjbzU0IuseJCtAIgNFwP+eR85Xl8hRNQ4R2c2yf76dPNEuoeqCO3JHQhv+4BRzBEAiBkw1FHD4I20KPTqL3AeOUNqGpOuLaS5emAG1QVvtaJbwIgf1iSkbXfxIStIQPXVCEROBJ4vzywHjPyCggI2+ZcL3utXLpa2BXSrjJh1a0hAnjWrVN8wQBWHKyqseZsKjyT1KbADbK/dU3ZtQvtGRfUrSED2EWRtp34hd38+1ZSPlfrF+wxQ0OjkKS/SRkKnTq6H3CtIQIp4HGlzJfsJ5Qxs2vbhNkPAy2IVLwIuFJ8KOQ3LB7I160hA2tPdrY27kCZqiqyuA1ThwdfN3l2IFKClcD4MQ45Vc84rSECGNNyAwuQVTdKQEkUkpiXdjJ4FN8N+TbIkm6M4FjI4fetIQN9UOTZ1RhHNZ8GUaWecSTN5hfogT+XUxyk6DLhbpQgJq0hA7hokgG1dxYKzlxlacDV67iSOfAt1GGr0OdDl+yDRI1CrSEDb3sJZORbdqHhqHnh8b7t7J2jSB0yoYthUWYgTeGQ7nitIQO8AZDTE5KlwzK6IwMDOjOpjdYuo+vwAizOs3gK6m6tkq0hA9w/hcKq68t5hS9OH+DIsSlxNiSGmGvSygIAAAAAACIAIPO6bQ3BKTN8L3jT6Xphzut9aEz0BYAFUztkb2o85zm+AAAAAAABAStADQMAAAAAACIAIqApDLRb7OM5XwrS6ekODZx3I/N1QxFmCMtygOMM01D6AQgJCAAAAAAAAAAAAABySywQyxDam4W0WJCKLjCtIQPAXfRFPLKiMoXlTJN4bK/Axl+un8WYtEdSnpJvn40Idq0hAuMFGA67XEfycM+cv8H8Ie3ns8TJcz0JyGCmZY5O33bFrSEDGDL+raIG0v5JGyfWsMm1gdQEQBPHvbtUiDkgsVmyx8WtIQLMclBt+PX2QvXZADscZn+JWKm1i/wBqrPT1LUz4nADr60hA92c0KzXLSHKkcf0RftznhACyyp7tYWSp7rukPrapY9arSED78UnO26YHVioaluCUwb2ecajn992f3z8LsEV6aWy8cutAy74ALJoAAEBK1gbAACi3D3z/YSEvsSx7aoxXsbqO8Mi308P4P0onwFIMEUCIQDakGescvbaIXTyWSuZBDlNuTfwFaMWv1dSPwH8kVJakgIgEEoX+jveT1quZLTlC+iTvK7Fm5Qi0WgNTrLqBMpfnTkB/Z0JVSEDA0Y8QdJzzQlaj7olkxen+xARajIYlKGjXNg4DhzeqfYhAnjvw3ebzUXzdWtz4a6nV479vwTjODjB5vQzKEdQokY7IQJod9378BNTJYZk7Lvi+VPutLex/k/12aLWTgggP9ynpSEDIUuKdz4Mueiyg/o6C+iqZqW8gI6gKWiogUi7hsHpU+khAswfYu0Z1zOZl4VUlsXxN0zJ503GNJSW3NuNVvCl2mGsVa5kdqkUTXxCNtgRdxqbgamb3IUPsw+DAt+IrXapFIojv9bX8TMi+rPZVW8ikLhXoPXiiK12qRQj1G7QtmCSlKXYQ+jc4RRlkxByJIitdqkUjjNAb6Q07NmiXE6bTWZGpP/aw2aIrXapFDvY3rX0TBKBm19KQInT0H6Eb/tHiK12qRR7r1bTqTfWIido/K4Q/Anp2KjSRIitdqkU0sd8M0+60ojNEWiE/PRoM8C6pXGIrXapFPCHYojbq+rHx+iKgrJShR6AtqSniK12qRSFsqVzM0auOyehfj7CC4adBFUZfYitdqkUcHtclNCcldXWKJ/AOIBqQrrVIIaIrXapFO/qUsXNyGvv/de52Eq6fJZq+lXdiK12qRSnYue0PLnToC9XhUqM6w/elKNzaYitdqkUptyNIzW5JpKQXtoNHobTdCly6n2IrXapFB/uI/apG/uZr2NJuoOa7wINStLSiK12qRThOGFLNBnYyjbzU0IuseJCtAIgNFwP+eR85Xl8hRNQ4R2c2yf76dPNEuoeqCO3JHQhv+4BRzBEAiBkw1FHD4I20KPTqL3AeOUNqGpOuLaS5emAG1QVvtaJbwIgf1iSkbXfxIStIQPXVCEROBJ4vzywHjPyCggI2+ZcL3utXLpa2BXSrjJh1a0hAnjWrVN8wQBWHKyqseZsKjyT1KbADbK/dU3ZtQvtGRfUrSED2EWRtp34hd38+1ZSPlfrF+wxQ0OjkKS/SRkKnTq6H3CtIQIp4HGlzJfsJ5Qxs2vbhNkPAy2IVLwIuFJ8KOQ3LB7I160hA2tPdrY27kCZqiqyuA1ThwdfN3l2IFKClcD4MQ45Vc84rSECGNNyAwuQVTdKQEkUkpiXdjJ4FN8N+TbIkm6M4FjI4fetIQN9UOTZ1RhHNZ8GUaWecSTN5hfogT+XUxyk6DLhbpQgJq0hA7hokgG1dxYKzlxlacDV67iSOfAt1GGr0OdDl+yDRI1CrSEDb3sJZORbdqHhqHnh8b7t7J2jSB0yoYthUWYgTeGQ7nitIQO8AZDTE5KlwzK6IwMDOjOpjdYuIQLxfznWiM8dm+c+wlTrKE6qoMj39PmxKXSwl8Rx73YWe60hAkww/bDWDZFeNPUMIEpBwaMvrAtM9cdV4aN/rPKI/zltrSECKhuPwa8K2MnTQnPZws1Mh87xYOSDEJHcBhgfYR6VVNCtIQNpUdfjSxfxjgriHZz4FSNZ3qzee4mv9ZZ9OT++cvxgvq0hAzIQGPnN3PIVJu7QrQBgyeiagxq2KrKl8mGgzdxBUfdkrSED5gyZ+Eut7bDnPP/ds0a8Uatm21aZfPO7a0OouXhi2R+tIQKi").unwrap();
        let sign_msg = SignRequest { tx: spend_tx };
        process_sign_message(
            &test_framework.config,
            sign_msg,
            &test_framework.bitcoin_privkey,
        )
        .unwrap_err();
    }
}
