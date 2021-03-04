use crate::{
    config::{config_folder_path, Config},
    cosignerd::create_datadir,
    utils::keys::{
        read_bitcoin_keys_file, read_noise_keys_file,
        tests::{create_bitcoin_seed_file, create_noise_keys_file, generate_bitcoin_seed},
    },
};
use revault_tx::{
    miniscript::{
        bitcoin::{
            self, secp256k1,
            util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey},
            Network, OutPoint, Transaction, TxIn, TxOut,
        },
        DescriptorPublicKey, DescriptorPublicKeyCtx, NullCtx,
    },
    scripts::{cpfp_descriptor, deposit_descriptor, unvault_descriptor, UnvaultDescriptor},
    transactions::{DepositTransaction, SpendTransaction, UnvaultTransaction},
    txins::DepositTxIn,
    txouts::{DepositTxOut, ExternalTxOut, SpendTxOut},
};
use std::{
    fs::{self, remove_file, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

#[derive(Debug, PartialEq)]
enum TestState {
    Uninitialized,
    Initialized,
    Configured,
}

#[derive(Debug)]
pub struct CosignerTestBuilder {
    state: TestState,
    n_man: u8,
    n_stk: u8,
    config_path: PathBuf,
}

impl CosignerTestBuilder {
    pub fn new(n_man: u8, n_stk: u8) -> Self {
        let config_path = config_folder_path()
            .map(|mut path| {
                path.push("conf.toml");
                path
            })
            .expect("Constructing config path");

        CosignerTestBuilder {
            state: TestState::Uninitialized,
            n_man: n_man,
            n_stk: n_stk,
            config_path: config_path,
        }
    }

    fn data_dir(&self) -> PathBuf {
        let network = bitcoin::Network::Testnet;
        let mut data_dir = config_folder_path().expect("Creating data_dir");

        data_dir.push(network.to_string());
        if !data_dir.as_path().exists() {
            create_datadir(&data_dir).expect("CosignerTestBuilder failed to create data_dir");
        }
        data_dir = fs::canonicalize(data_dir).expect("Canonicalize data_dir");
        data_dir
    }

    fn initialize_cosigner(&self) {
        create_bitcoin_seed_file(
            [self.data_dir(), PathBuf::from("cosigner_bitcoin.keys")]
                .iter()
                .collect(),
        )
        .expect("Creating cosigner bitcoin keys file");
        create_noise_keys_file(
            [self.data_dir(), PathBuf::from("cosigner_noise.keys")]
                .iter()
                .collect(),
        )
        .expect("Creating cosigner noise keys file");
    }

    fn initialize_managers(&self) {
        for manager in 1..=self.n_man {
            create_bitcoin_seed_file(
                [
                    self.data_dir(),
                    PathBuf::from(format!("manager_{:?}_bitcoin.keys", manager)),
                ]
                .iter()
                .collect(),
            )
            .expect(&(format!("Creating bitcoin keys file for manager {:?}", manager)));
            create_noise_keys_file(
                [
                    self.data_dir(),
                    PathBuf::from(format!("manager_{:?}_noise.keys", manager)),
                ]
                .iter()
                .collect(),
            )
            .expect(&(format!("Creating noise keys file for manager {:?}", manager)));
        }
    }

    pub fn initialize(mut self) -> Self {
        self.initialize_cosigner();
        self.initialize_managers();
        self.state = TestState::Initialized;
        self
    }

    pub fn configure(mut self) -> Self {
        if self.state != TestState::Initialized {
            panic!("Cannot configure if state != TestState::Initialized");
        }
        // write toml config file
        let mut toml_str = String::new();
        toml_str.push_str("network = \"testnet\"\n");

        // This cosigner and managers keys are already initialized since
        // (public, private) bitcoin and noise keypairs are required for them.
        let xpub = read_bitcoin_keys_file(
            [self.data_dir(), PathBuf::from("cosigner_bitcoin.keys")]
                .iter()
                .collect(),
        )
        .expect("Reading cosigner bitcoin keys file")
        .1;
        toml_str.push_str(&(format!("[cosigner_keys]\nxpub = {:?}\n", xpub.to_string())));
        for manager in 1..self.n_man {
            let man_xpub = read_bitcoin_keys_file(
                [
                    self.data_dir(),
                    PathBuf::from(format!("manager_{:?}_bitcoin.keys", manager)),
                ]
                .iter()
                .collect(),
            )
            .expect(&(format!("Reading manager_{:?}_bitcoin.keys", manager)))
            .1;
            let man_noise_pub = read_noise_keys_file(
                [
                    self.data_dir(),
                    PathBuf::from(format!("manager_{:?}_noise.keys", manager)),
                ]
                .iter()
                .collect(),
            )
            .expect(&(format!("Reading manager_{:?}_noise.keys", manager)))
            .1;
            toml_str.push_str(
                &(format!(
                    "[[managers]]\nxpub = {:?}\nnoise_pubkey = \"{:?}\"\n",
                    man_xpub.to_string(),
                    man_noise_pub.0
                )),
            );
        }

        // For stakeholders and the remaining cosigners, only bitcoin pubkeys are
        // needed so we generate them here and add them to the test framework
        // config.toml file
        let secp = secp256k1::Secp256k1::new();
        // FIXME: For some reason this inclusive range end is needed?
        let keys: Vec<ExtendedPubKey> = (1..=(2 * self.n_stk))
            .map(|_| generate_bitcoin_seed().expect("generating a bitcoin seed"))
            .map(|seed| {
                ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
                    .expect("converting seed to ExtendedPrivKey")
            })
            .map(|xpriv| ExtendedPubKey::from_private(&secp, &xpriv))
            .collect();

        let mut cosigners = keys[(self.n_stk + 1) as usize..(2 * self.n_stk as usize)].to_vec();
        cosigners.push(xpub);
        let stakeholders = keys[1..=self.n_stk as usize].to_vec();

        for (stk_pub, cos_pub) in stakeholders.iter().zip(cosigners.iter()) {
            toml_str.push_str(
                &(format!(
                    "[[stakeholders]]\nxpub = {:?}\ncosigner_key = {:?}\n",
                    stk_pub.to_string(),
                    cos_pub.to_string()
                )),
            );
        }

        let mut conf = File::create(&self.config_path).expect("Creating config file");
        write!(conf, "{}", &toml_str).expect("Writing to config file");
        self.state = TestState::Configured;
        self
    }

    pub fn get_config_path(&self) -> PathBuf {
        PathBuf::from(&self.config_path)
    }

    pub fn get_unvault_descriptor(
        &self,
        csv: u32,
        thresh: usize,
    ) -> UnvaultDescriptor<DescriptorPublicKey> {
        let config = Config::from_file(Some(self.get_config_path())).expect("Constructing Config");
        let mut stakeholders: Vec<DescriptorPublicKey> = Vec::new();
        let mut cosigners: Vec<DescriptorPublicKey> = Vec::new();
        for stk in config.stakeholders {
            stakeholders.push(stk.xpub);
            cosigners.push(stk.cosigner_key);
        }
        let mut managers: Vec<DescriptorPublicKey> = Vec::new();
        for man in config.managers {
            managers.push(man.xpub);
        }

        unvault_descriptor(
            stakeholders.clone(),
            managers.clone(),
            thresh,
            cosigners.clone(),
            csv,
        )
        .expect("Unvault descriptor generation error")
    }

    /// To test signing, database and transport and functionalities, we need
    /// spend transactions where the cosigning server is a valid participant
    /// and can add their signature.
    pub fn generate_spend_tx(&self, csv: u32, thresh: usize) -> SpendTransaction {
        if self.state != TestState::Configured {
            panic!("Cannot generate spend transaction if TestBuilder hasn't been Configured");
        }

        // First define the set of participants using vectors of public keys.
        // Generate enough keys for the stakeholders and other cosigners.
        // This cosigner and other managers' keys are already initialized.
        let config = Config::from_file(Some(self.get_config_path())).expect("Constructing Config");
        let mut stakeholders: Vec<DescriptorPublicKey> = Vec::new();
        let mut cosigners: Vec<DescriptorPublicKey> = Vec::new();
        for stk in config.stakeholders {
            stakeholders.push(stk.xpub);
            cosigners.push(stk.cosigner_key);
        }
        let mut managers: Vec<DescriptorPublicKey> = Vec::new();
        for man in config.managers {
            managers.push(man.xpub);
        }

        // Now create the script descriptors
        let unvault_descriptor = unvault_descriptor(
            stakeholders.clone(),
            managers.clone(),
            thresh,
            cosigners.clone(),
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            cpfp_descriptor(managers).expect("Unvault CPFP descriptor generation error");
        let deposit_descriptor =
            deposit_descriptor(stakeholders).expect("Vault descriptor generation error");

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

impl Drop for CosignerTestBuilder {
    fn drop(&mut self) {
        if self.state != TestState::Uninitialized {
            remove_file(
                [self.data_dir(), PathBuf::from("cosigner_bitcoin.keys")]
                    .iter()
                    .collect::<PathBuf>(),
            )
            .expect("Removing cosigner_bitcoin.keys");
            remove_file(
                [self.data_dir(), PathBuf::from("cosigner_noise.keys")]
                    .iter()
                    .collect::<PathBuf>(),
            )
            .expect("Removing cosigner_noise.keys");
            for manager in 1..=self.n_man {
                remove_file(
                    [
                        self.data_dir(),
                        PathBuf::from(format!("manager_{:?}_bitcoin.keys", manager)),
                    ]
                    .iter()
                    .collect::<PathBuf>(),
                )
                .expect(&(format!("Removing bitcoin keys file for manager {:?}", manager)));
                remove_file(
                    [
                        self.data_dir(),
                        PathBuf::from(format!("manager_{:?}_noise.keys", manager)),
                    ]
                    .iter()
                    .collect::<PathBuf>(),
                )
                .expect(&(format!("Removing noise keys file for manager {:?}", manager)));
            }
        }
        if self.state == TestState::Configured {
            remove_file(&self.config_path).expect("Removing conf.toml");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_builder() {
        let test_framework = CosignerTestBuilder::new(4, 5).initialize().configure();
        test_framework.generate_spend_tx(10, 2);
        test_framework.get_unvault_descriptor(10, 2);
    }
}
