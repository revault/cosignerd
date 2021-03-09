use crate::{config::ManagerConfig, cosignerd::CosignerD, database::setup_db};
use revault_net::sodiumoxide;
use revault_tx::{
    miniscript::{
        bitcoin::{
            secp256k1,
            secp256k1::rand::{rngs::SmallRng, FromEntropy, RngCore},
            util::bip32::{self, ChildNumber},
            Network, OutPoint, TxOut,
        },
        descriptor::{
            DescriptorPublicKey, DescriptorPublicKeyCtx, DescriptorSinglePub, DescriptorXKey,
        },
    },
    scripts::{cpfp_descriptor, unvault_descriptor},
    transactions::SpendTransaction,
    txins::UnvaultTxIn,
    txouts::{ExternalTxOut, SpendTxOut, UnvaultTxOut},
};

use std::{fs, net::SocketAddr, path::PathBuf, str::FromStr};

use libc;

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

    // Use a scratch directory in /tmp
    let data_dir = unsafe {
        let template = String::from("cosignerd-XXXXXX").into_bytes();
        let mut template = std::mem::ManuallyDrop::new(template);
        let template_ptr = template.as_mut_ptr() as *mut i8;
        libc::mkdtemp(template_ptr);
        let datadir_str =
            String::from_raw_parts(template_ptr as *mut u8, template.len(), template.capacity());
        assert!(!datadir_str.contains("XXXXXX"), "mkdtemp failed");
        datadir_str
    };
    let data_dir: PathBuf = ["/tmp", &data_dir].iter().collect();
    if data_dir.as_path().exists() {
        fs::remove_dir_all(&data_dir).expect("Removing former scratch datadir");
    }
    fs::create_dir(&data_dir).expect("Creating scratch datadir in /tmp");
    let listen = SocketAddr::from_str("127.0.0.1:8383").unwrap();

    let noise_privkey = sodiumoxide::crypto::box_::gen_keypair().1;
    let bitcoin_privkey = secp256k1::SecretKey::new(&mut rng);

    let mut db_path = data_dir.clone();
    db_path.push("cosignerd.sqlite3");
    setup_db(&db_path).expect("Setting up db");

    CosignerD {
        managers,
        noise_privkey,
        bitcoin_privkey,
        data_dir,
        listen,
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

    pub fn generate_spend_tx(&self, outpoints: &[OutPoint]) -> SpendTransaction {
        let mut rng = SmallRng::from_entropy();
        let secp = secp256k1::Secp256k1::new();
        let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, ChildNumber::from(0));
        let unvault_value: u64 = 100000000;
        let n_stk = 10;
        let csv = 12;

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
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor = cpfp_descriptor(managers_keys).expect("CPFP desc generation error");

        let unvault_txins: Vec<UnvaultTxIn> = outpoints
            .iter()
            .map(|o| {
                let unvault_txout = UnvaultTxOut::new(unvault_value, &unvault_descriptor, xpub_ctx);
                UnvaultTxIn::new(*o, unvault_txout, csv)
            })
            .collect();
        let spend_txo = ExternalTxOut::new(TxOut {
            value: unvault_value * unvault_txins.len() as u64 - 50_000 * unvault_txins.len() as u64, // FIXME: we could compute the actual price
            ..TxOut::default()
        });

        SpendTransaction::new(
            unvault_txins,
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
            true,
        )
        .expect("Creating spend transaction")
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let test_framework = CosignerTestBuilder::new(5);
        test_framework.generate_spend_tx(&[
            OutPoint::from_str(
                "2b8930127e9dfd1bcdf35df2bc7f3b8cdbec083b1ae693f36b6305fccd1425da:0",
            )
            .unwrap(),
            OutPoint::from_str(
                "ceca4de398c63b29543f8346c09fd7522fd8661ce8bdc0e454e8d6ed8ad46a0d:1",
            )
            .unwrap(),
            OutPoint::from_str(
                "0b38682347207cd79de33edf8897a75abe7d8799b194439150306773b6aef55a:189",
            )
            .unwrap(),
        ]);
    }
}
