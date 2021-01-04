use revault_net::{
    error::Error as NetError,
    noise::{NoisePrivKey, NoisePubKey},
};
use revault_tx::bitcoin::{
    secp256k1,
    secp256k1::rand::{rngs::StdRng, FromEntropy, RngCore},
    util::bip32::{ExtendedPrivKey, ExtendedPubKey},
    Network,
};
use std::{
    convert::TryInto,
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    path::PathBuf,
};

pub fn read_noise_keys_file(path: PathBuf) -> Result<(NoisePrivKey, NoisePubKey), Error> {
    let mut noise_keys_file = File::open(path)?;
    let mut priv_buf = [0u8; 32];
    let mut pub_buf = [0u8; 32];
    noise_keys_file.read_exact(&mut priv_buf)?;
    noise_keys_file.read_exact(&mut pub_buf)?;
    let privkey = NoisePrivKey(priv_buf);
    let pubkey = NoisePubKey(pub_buf);
    Ok((privkey, pubkey))
}

// FIXME: When storage format is specified re-write this
pub fn read_bitcoin_keys_file(path: PathBuf) -> Result<(ExtendedPrivKey, ExtendedPubKey), Error> {
    let mut bitcoin_seed_file = File::open(path)?;
    let mut seed = [0u8; 64];
    bitcoin_seed_file.read_exact(&mut seed)?;

    let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("Failed to construct xpriv: {:?}", e),
        )
    })?;

    let secp = secp256k1::Secp256k1::new();
    let xpub = ExtendedPubKey::from_private(&secp, &xpriv);

    Ok((xpriv, xpub))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, Keypair};
    use std::fs::remove_file;

    fn get_noise_params() -> Result<NoiseParams, NetError> {
        let noise_params: NoiseParams = "Noise_KX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| NetError::Noise(format!("Invalid Noise Pattern: {}", e)))?;
        Ok(noise_params)
    }

    /// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
    /// when generating a static key pair for secure communication.
    fn generate_keypair(noise_params: NoiseParams) -> Keypair {
        Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
            .generate_keypair()
            .unwrap()
    }

    fn generate_noise_keys() -> Result<(NoisePrivKey, NoisePubKey), Error> {
        let noise_params = get_noise_params().unwrap();
        let keypair = generate_keypair(noise_params);
        Ok((
            NoisePrivKey(keypair.private[..].try_into().unwrap()),
            NoisePubKey(keypair.public[..].try_into().unwrap()),
        ))
    }

    pub fn create_noise_keys_file(path: PathBuf) -> Result<(), Error> {
        let mut noise_keys_file = File::create(path)?;
        let noise_keys = generate_noise_keys()?;
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&(noise_keys.0).0);
        buf[32..].copy_from_slice(&(noise_keys.1).0);
        noise_keys_file.write_all(&buf)?;
        Ok(())
    }

    pub fn generate_bitcoin_seed() -> Result<[u8; 64], Error> {
        let mut rand_bytes = [0u8; 64];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut rand_bytes);
        Ok(rand_bytes)
    }

    pub fn create_bitcoin_seed_file(path: PathBuf) -> Result<(), Error> {
        let mut bitcoin_seed_file = File::create(path)?;
        let bitcoin_seed = generate_bitcoin_seed()?;
        bitcoin_seed_file.write_all(&bitcoin_seed)?;
        Ok(())
    }

    #[test]
    fn test_bitcoin_keys_rw() {
        create_bitcoin_seed_file(PathBuf::from("bitcoin.keys"))
            .expect("Initializing bitcoin keys file");
        read_bitcoin_keys_file(PathBuf::from("bitcoin.keys")).expect("Reading bitcoin keys file");
        remove_file("bitcoin.keys").expect("Deleting bitcoin keys file");
    }

    #[test]
    fn test_noise_keys_rw() {
        create_noise_keys_file(PathBuf::from("noise.keys")).expect("Initializing noise keys file");
        read_noise_keys_file(PathBuf::from("noise.keys")).expect("Reading noise keys file");
        remove_file("noise.keys").expect("Deleting noise keys file")
    }
}
