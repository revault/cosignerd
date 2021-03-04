use crate::{
    config::{config_file_path, datadir_path, Config, ManagerConfig},
    cosignerd::{create_datadir, CosignerD},
    utils::keys::{
        read_bitcoin_keys_file, read_noise_keys_file,
        tests::{create_bitcoin_seed_file, create_noise_keys_file, generate_bitcoin_seed},
    },
};
use revault_net::sodiumoxide;
use revault_tx::{
    miniscript::{
        bitcoin::{
            self, secp256k1,
            secp256k1::rand::{rngs::SmallRng, FromEntropy, RngCore},
            util::bip32::{self, ChildNumber, ExtendedPrivKey, ExtendedPubKey},
            Network, OutPoint, Transaction, TxIn, TxOut,
        },
        descriptor::{
            DescriptorPublicKey, DescriptorPublicKeyCtx, DescriptorSinglePub, DescriptorXKey,
        },
        NullCtx,
    },
    scripts::{cpfp_descriptor, deposit_descriptor, unvault_descriptor, UnvaultDescriptor},
    transactions::{DepositTransaction, SpendTransaction, UnvaultTransaction},
    txins::DepositTxIn,
    txouts::{DepositTxOut, ExternalTxOut, SpendTxOut},
};
use std::{
    fs::{self, remove_file, File},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

fn random_privkey(rng: &mut SmallRng) -> bip32::ExtendedPrivKey {
    let mut rand_bytes = [0u8; 64];

    rng.fill_bytes(&mut rand_bytes);

    bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
        .unwrap_or_else(|_| random_privkey(rng))
}

fn cosignerd(n_man: usize, n_stk: usize) -> CosignerD {
    let mut rng = SmallRng::from_entropy();
    let secp = secp256k1::Secp256k1::new();

    let mut managers = Vec::with_capacity(n_man);
    for _ in 0..n_man {
        let xpub = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng)),
            derivation_path: bip32::DerivationPath::from(vec![]),
            is_wildcard: true,
        });
        let noise_key = sodiumoxide::crypto::box_::gen_keypair().0;
        managers.push(ManagerConfig { xpub, noise_key });
    }

    let mut stakeholders_keys = Vec::with_capacity(n_stk);
    let mut cosigners_keys = Vec::with_capacity(n_stk);
    for _ in 0..n_stk {
        stakeholders_keys.push(DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng)),
            derivation_path: bip32::DerivationPath::from(vec![]),
            is_wildcard: true,
        }));
        cosigners_keys.push(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
            origin: None,
            key: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng)).public_key,
        }));
    }

    // Use a scratch directory at the root of the repo
    let mut data_dir = PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    data_dir.push("scratch_datadir");
    let addr = SocketAddr::from_str("127.0.0.1:9999").unwrap();

    CosignerD {
        stakeholders_keys,
        managers,
        cosigners_keys,
        data_dir,
        addr,
    }
}

#[derive(Debug)]
pub struct CosignerTestBuilder {
    pub cosignerd: CosignerD,
}

impl CosignerTestBuilder {
    pub fn new(n_man: usize, n_stk: usize) -> Self {
        let cosignerd = cosignerd(n_man, n_stk);
        CosignerTestBuilder { cosignerd }
    }

    /// To test signing, database and transport and functionalities, we need
    /// spend transactions where the cosigning server is a valid participant
    /// and can add their signature.
    pub fn generate_spend_tx(&self, csv: u32, thresh: usize) -> SpendTransaction {
        // FIXME: descriptors should be part of CosignerD !!
        let man_xpubs: Vec<DescriptorPublicKey> = self
            .cosignerd
            .managers
            .clone()
            .into_iter()
            .map(|m| m.xpub)
            .collect();

        let unvault_descriptor = unvault_descriptor(
            self.cosignerd.stakeholders_keys.clone(),
            man_xpubs.clone(),
            thresh,
            self.cosignerd.cosigners_keys.clone(),
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            cpfp_descriptor(man_xpubs).expect("Unvault CPFP descriptor generation error");
        let deposit_descriptor = deposit_descriptor(self.cosignerd.stakeholders_keys.clone())
            .expect("Vault descriptor generation error");

        // Proceed to creating transactions. First, the vault (deposit) transaction.
        let secp = secp256k1::Secp256k1::new();
        let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, ChildNumber::from(0));
        let deposit_value: u64 = 100000000;

        let vault_scriptpubkey = unvault_descriptor.0.script_pubkey(xpub_ctx);
        let vault_raw_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::from_str(
                    "39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0",
                )
                .unwrap(),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: deposit_value,
                script_pubkey: vault_scriptpubkey.clone(),
            }],
        };
        let vault_txo =
            DepositTxOut::new(vault_raw_tx.output[0].value, &deposit_descriptor, xpub_ctx);
        let vault_tx = DepositTransaction(vault_raw_tx);

        // Now the unvault transaction.
        let vault_txin = DepositTxIn::new(
            OutPoint {
                txid: vault_tx.0.txid(),
                vout: 0,
            },
            vault_txo.clone(),
        );

        let unvault_tx = UnvaultTransaction::new(
            vault_txin,
            &unvault_descriptor,
            &cpfp_descriptor,
            xpub_ctx,
            csv,
        )
        .expect("Creating unvault transaction");

        // Now the spend transaction.
        let unvault_txin = unvault_tx.spend_unvault_txin(&unvault_descriptor, xpub_ctx, csv);
        let spend_txo = ExternalTxOut::new(TxOut {
            value: deposit_value - 50_000 - 50_000,
            ..TxOut::default()
        });

        SpendTransaction::new(
            vec![unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
            true,
        )
        .expect("Creating spend transaction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_builder() {
        let test_framework = CosignerTestBuilder::new(4, 5);
        test_framework.generate_spend_tx(10, 2);
    }
}
