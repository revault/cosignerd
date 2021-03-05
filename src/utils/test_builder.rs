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
    txins::UnvaultTxIn,
    txouts::{ExternalTxOut, SpendTxOut, UnvaultTxOut},
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

fn cosignerd(n_man: usize) -> CosignerD {
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
    if data_dir.as_path().exists() {
        fs::remove_dir_all(&data_dir).expect("Removing former scratch datadir");
    }
    fs::create_dir(&data_dir).expect("Creating scratch datadir");
    let addr = SocketAddr::from_str("127.0.0.1:9999").unwrap();

    CosignerD {
        managers,
        data_dir,
        addr,
    }
}

#[derive(Debug)]
pub struct CosignerTestBuilder {
    pub cosignerd: CosignerD,
}

impl CosignerTestBuilder {
    pub fn new(n_man: usize) -> Self {
        let cosignerd = cosignerd(n_man);
        CosignerTestBuilder { cosignerd }
    }

    /// To test signing, database and transport and functionalities, we need
    /// spend transactions where the cosigning server is a valid participant
    /// and can add their signature.
    pub fn generate_spend_tx(&self, n_stk: usize, csv: u32, thresh: usize) -> SpendTransaction {
        let mut rng = SmallRng::from_entropy();
        let secp = secp256k1::Secp256k1::new();
        let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, ChildNumber::from(0));
        let unvault_value: u64 = 100000000;

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
                key: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng))
                    .public_key,
            }));
        }
        let managers_keys: Vec<DescriptorPublicKey> = self
            .cosignerd
            .managers
            .clone()
            .iter()
            .map(|m| m.xpub.clone())
            .collect();
        let unvault_descriptor = unvault_descriptor(
            stakeholders_keys,
            managers_keys.clone(),
            1,
            cosigners_keys,
            18,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor = cpfp_descriptor(managers_keys).expect("CPFP desc generation error");

        let unvault_txout = UnvaultTxOut::new(unvault_value, &unvault_descriptor, xpub_ctx);
        let unvault_txin = UnvaultTxIn::new(
            OutPoint::from_str(
                "2b8930127e9dfd1bcdf35df2bc7f3b8cdbec083b1ae693f36b6305fccd1425da:0",
            )
            .unwrap(),
            unvault_txout,
            csv,
        );
        let spend_txo = ExternalTxOut::new(TxOut {
            value: unvault_value - 50_000, // FIXME: we could compute the actual price
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
        let test_framework = CosignerTestBuilder::new(5);
        test_framework.generate_spend_tx(5, 10, 2);
    }
}
