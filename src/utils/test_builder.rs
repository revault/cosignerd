use crate::{
    config::Config,
    utils::keys::{
        read_bitcoin_keys_file, read_noise_keys_file,
        tests::{create_bitcoin_seed_file, create_noise_keys_file, generate_bitcoin_seed},
    },
};
use revault_tx::{
    miniscript::{
        bitcoin::{
            self, secp256k1,
            util::bip32::{ExtendedPrivKey, ExtendedPubKey},
            Network, OutPoint, PublicKey, Transaction, TxIn, TxOut,
        },
        NullCtx,
    },
    scripts::{self, cpfp_descriptor, unvault_descriptor, vault_descriptor},
    transactions::{SpendTransaction, UnvaultTransaction, VaultTransaction},
    txins::VaultTxIn,
    txouts::{ExternalTxOut, SpendTxOut, UnvaultTxOut, VaultTxOut},
};
use std::{
    fs::{remove_file, File},
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

/// A CosignerTestBuilder type to simplify setup and teardown needed for tests.
// setup :
//      *done* generate bitcoin.keys and noise.keys files
//      *done* generate set of managers bitcoin.keys and noise.keys files
//      *done* generate config file which includes set of managers' noise pubkeys
//      Construct client channel and enact handshake as one of managers
//      *done* generate a new valid spend_tx (with inputs locked to a valid script
//             including servers' bitcoin pubkey)
//      Send SpendTx message to server from client
//      Receive server's response to SpendTx
// teardown :
//      remove cosigner's bitcoin.keys and noise.keys files
//      remove set of managers bitcoin.keys and noise.keys files
//      remove config file
//      remove db file
#[derive(Debug)]
pub struct CosignerTestBuilder {
    state: TestState,
    nman: u8,
}

impl CosignerTestBuilder {
    pub fn new(nman: u8) -> Self {
        CosignerTestBuilder {
            state: TestState::Uninitialized,
            nman: nman,
        }
    }

    fn initialize_cosigner(&self) {
        create_bitcoin_seed_file(PathBuf::from("cosigner_bitcoin.keys"))
            .expect("Creating cosigner bitcoin keys file");
        create_noise_keys_file(PathBuf::from("cosigner_noise.keys"))
            .expect("Creating cosigner noise keys file");
    }

    fn initialize_managers(&self) {
        for manager in 1..=self.nman {
            create_bitcoin_seed_file(PathBuf::from(format!("manager_{:?}_bitcoin.keys", manager)))
                .expect(&(format!("Creating bitcoin keys file for manager {:?}", manager)));
            create_noise_keys_file(PathBuf::from(format!("manager_{:?}_noise.keys", manager)))
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
        toml_str.push_str("network = \"bitcoin\"\n");

        let xpub = read_bitcoin_keys_file(PathBuf::from("cosigner_bitcoin.keys"))
            .expect("Reading cosigner bitcoin keys file")
            .1;
        toml_str.push_str(&(format!("[cosigner_keys]\nxpub = {:?}\n", xpub.to_string())));
        for manager in 1..self.nman {
            let man_xpub = read_bitcoin_keys_file(PathBuf::from(format!(
                "manager_{:?}_bitcoin.keys",
                manager
            )))
            .expect(&(format!("Reading manager_{:?}_bitcoin.keys", manager)))
            .1;
            let man_noise_pub =
                read_noise_keys_file(PathBuf::from(format!("manager_{:?}_noise.keys", manager)))
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
        let mut conf = File::create("conf.toml").expect("Creating config file");
        write!(conf, "{}", &toml_str).expect("Writing to config file");
        self.state = TestState::Configured;
        self
    }

    /// To test signing, database and transport and functionalities, we need
    /// spend transactions where the cosigning server is a valid participant
    /// and can add their signature.
    pub fn generate_spend_tx(&self, n_stk: u8, csv: u32) -> SpendTransaction {
        if self.state != TestState::Configured {
            panic!("Cannot generate spend transaction if TestBuilder hasn't been Configured");
        }

        // First define the set of participants using vectors of public keys.
        // Generate enough keys for the stakeholders and other cosigners.
        // This cosigner and other managers' keys are already initialized.
        let secp = secp256k1::Secp256k1::new();
        let keys: Vec<PublicKey> = (1..=(2 * n_stk))
            .map(|_| generate_bitcoin_seed().expect("generating a bitcoin seed"))
            .map(|seed| {
                ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
                    .expect("converting seed to ExtendedPrivKey")
            })
            .map(|xpriv| ExtendedPubKey::from_private(&secp, &xpriv).public_key)
            .collect();

        let mut managers = Vec::new();
        for manager in 1..=self.nman {
            managers.push(
                read_bitcoin_keys_file(PathBuf::from(format!(
                    "manager_{:?}_bitcoin.keys",
                    manager
                )))
                .unwrap()
                .1
                .public_key,
            );
        }

        let my_pubkey = read_bitcoin_keys_file(PathBuf::from("cosigner_bitcoin.keys"))
            .unwrap()
            .1
            .public_key;
        let mut cosigners = keys[n_stk as usize + 1..].to_vec();
        cosigners.push(my_pubkey);
        let stakeholders = keys[1..=n_stk as usize].to_vec();

        // Now create the script descriptors
        let unvault_descriptor = unvault_descriptor(
            stakeholders.clone(),
            managers.clone(),
            2,
            cosigners.clone(),
            csv,
        )
        .expect("Unvault descriptor generation error");
        let cpfp_descriptor =
            cpfp_descriptor(managers).expect("Unvault CPFP descriptor generation error");
        let vault_descriptor =
            vault_descriptor(stakeholders).expect("Vault descriptor generation error");

        // Proceed to creating transactions. First, the vault (deposit) transaction.
        let xpub_ctx = NullCtx;
        let deposit_value: u64 = 100000000;

        let vault_scriptpubkey = vault_descriptor.0.script_pubkey(xpub_ctx);
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
        let vault_txo = VaultTxOut::new(vault_raw_tx.output[0].value, &vault_descriptor, xpub_ctx);
        let vault_tx = VaultTransaction(vault_raw_tx);

        // Now the unvault transaction.
        let vault_txin = VaultTxIn::new(
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
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, csv)
            .unwrap();
        let spend_txo = ExternalTxOut::new(TxOut {
            value: 1,
            ..TxOut::default()
        });

        SpendTransaction::new(
            vec![unvault_txin],
            vec![SpendTxOut::Destination(spend_txo.clone())],
            &cpfp_descriptor,
            xpub_ctx,
            0,
        )
    }
}

impl Drop for CosignerTestBuilder {
    fn drop(&mut self) {
        if self.state != TestState::Uninitialized {
            remove_file("cosigner_bitcoin.keys").expect("Removing cosigner_bitcoin.keys");
            remove_file("cosigner_noise.keys").expect("Removing cosigner_noise.keys");
            for manager in 1..=self.nman {
                remove_file(format!("manager_{:?}_bitcoin.keys", manager))
                    .expect(&(format!("Removing bitcoin keys file for manager {:?}", manager)));
                remove_file(format!("manager_{:?}_noise.keys", manager))
                    .expect(&(format!("Removing noise keys file for manager {:?}", manager)));
            }
        }
        if self.state == TestState::Configured {
            remove_file("conf.toml").expect("Removing conf.toml");
        }
        // TODO: remove db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_builder() {
        let test_framework = CosignerTestBuilder::new(4).initialize().configure();
        test_framework.generate_spend_tx(4, 5);
    }
}
