use crate::{config::Config, config::ManagerConfig, database::setup_db};
use revault_net::{noise::SecretKey as NoisePrivkey, sodiumoxide};
use revault_tx::{
    miniscript::{
        bitcoin::{
            secp256k1,
            secp256k1::rand::{rngs::SmallRng, FromEntropy, RngCore},
            util::bip32,
            Amount, Network, OutPoint, TxOut,
        },
        descriptor::{DescriptorPublicKey, DescriptorSinglePub, DescriptorXKey, Wildcard},
    },
    scripts::{CpfpDescriptor, UnvaultDescriptor},
    transactions::SpendTransaction,
    txins::UnvaultTxIn,
    txouts::{SpendTxOut, UnvaultTxOut},
};

use std::{fs, net::SocketAddr, path::PathBuf, str::FromStr};

use libc;

fn random_privkey(rng: &mut SmallRng) -> bip32::ExtendedPrivKey {
    let mut rand_bytes = [0u8; 64];

    rng.fill_bytes(&mut rand_bytes);

    bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
        .unwrap_or_else(|_| random_privkey(rng))
}

#[derive(Debug)]
pub struct CosignerTestBuilder {
    pub config: Config,
    pub noise_privkey: NoisePrivkey,
    pub bitcoin_privkey: secp256k1::SecretKey,
    pub managers_keys: Vec<DescriptorPublicKey>,
    pub secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl CosignerTestBuilder {
    pub fn new(n_man: usize) -> Self {
        let mut rng = SmallRng::from_entropy();
        let secp = secp256k1::Secp256k1::new();

        let mut managers = Vec::with_capacity(n_man);
        let mut managers_keys = Vec::with_capacity(n_man);
        for _ in 0..n_man {
            let xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng)),
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::Unhardened,
            });
            managers_keys.push(xpub);

            let noise_key = sodiumoxide::crypto::box_::gen_keypair().0;
            managers.push(ManagerConfig { noise_key });
        }

        // Use a scratch directory in /tmp
        let data_dir_str = unsafe {
            let template = std::ffi::CString::new("/tmp/cosignerd-XXXXXX").unwrap();
            let template_ptr = template.into_raw();

            if libc::mkdtemp(template_ptr) == std::ptr::null_mut() {
                panic!(
                    "Error creating temp dir: '{}'",
                    std::io::Error::last_os_error(),
                )
            }
            std::ffi::CString::from_raw(template_ptr)
                .into_string()
                .unwrap()
        };
        let data_dir = PathBuf::from_str(&data_dir_str).unwrap();
        let listen = SocketAddr::from_str("127.0.0.1:8383").unwrap();

        let mut db_path = data_dir.clone();
        db_path.push("cosignerd.sqlite3");
        setup_db(&db_path).expect("Setting up db");

        let config = Config {
            managers,
            data_dir,
            listen,
            log_level: log::LevelFilter::Trace,
            daemon: false,
        };

        let noise_privkey = sodiumoxide::crypto::box_::gen_keypair().1;
        let bitcoin_privkey = secp256k1::SecretKey::new(&mut rng);

        CosignerTestBuilder {
            config,
            noise_privkey,
            bitcoin_privkey,
            managers_keys,
            secp,
        }
    }

    pub fn generate_spend_tx(&self, outpoints: &[OutPoint]) -> SpendTransaction {
        let mut rng = SmallRng::from_entropy();
        let secp = secp256k1::Secp256k1::new();
        let unvault_value = Amount::from_sat(100000000);
        let n_stk = 10;
        let csv = 12;

        let mut stakeholders_keys = Vec::with_capacity(n_stk);
        let mut cosigners_keys = Vec::with_capacity(n_stk);
        for _ in 0..n_stk {
            stakeholders_keys.push(DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng)),
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::Unhardened,
            }));
            cosigners_keys.push(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                origin: None,
                key: bip32::ExtendedPubKey::from_private(&secp, &random_privkey(&mut rng))
                    .public_key,
            }));
        }
        let unvault_descriptor = UnvaultDescriptor::new(
            stakeholders_keys,
            self.managers_keys.clone(),
            1,
            cosigners_keys,
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            CpfpDescriptor::new(self.managers_keys.clone()).expect("CPFP desc generation error");

        let unvault_txins: Vec<UnvaultTxIn> = outpoints
            .iter()
            .map(|o| {
                let unvault_txout =
                    UnvaultTxOut::new(unvault_value, &unvault_descriptor.derive(0.into(), &secp));
                UnvaultTxIn::new(*o, unvault_txout, csv)
            })
            .collect();
        let spend_txo = TxOut {
            value: unvault_value.as_sat() * unvault_txins.len() as u64
                - 50_000 * unvault_txins.len() as u64, // FIXME: we could compute the actual price
            ..TxOut::default()
        };

        SpendTransaction::new(
            unvault_txins,
            vec![SpendTxOut::new(spend_txo.clone())],
            None,
            &cpfp_descriptor.derive(0.into(), &secp),
            0,
            true,
        )
        .expect("Creating spend transaction")
    }
}

impl Drop for CosignerTestBuilder {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.config.data_dir).unwrap_or_else(|e| {
            eprintln!(
                "Error removing datadir at '{:?}': '{}'",
                self.config.data_dir, e
            );
            std::process::exit(1);
        });
    }
}

#[cfg(test)]
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
