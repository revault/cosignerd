use cosignerd::{
    config::Config,
    daemonize::daemonize,
    database::setup_db,
    keys::{read_bitcoin_privkey, read_or_create_noise_key},
    processing::process_sign_message,
};
use revault_net::{
    bitcoin::PrivateKey,
    message::{RequestParams, ResponseResult},
    noise::{PublicKey as NoisePubkey, SecretKey as NoisePrivkey},
    sodiumoxide::crypto::scalarmult::curve25519,
};
use revault_tx::bitcoin::{hashes::hex::ToHex, secp256k1};
use std::{env, fs, net::TcpListener, os::unix::fs::DirBuilderExt, path::PathBuf, process, time};

fn parse_args(args: Vec<String>) -> Option<PathBuf> {
    if args.len() == 1 {
        return None;
    }

    if args.len() != 3 {
        eprintln!("Unknown arguments '{:?}'.", args);
        eprintln!("Only '--conf <configuration file path>' is supported.");
        process::exit(1);
    }

    Some(PathBuf::from(args[2].to_owned()))
}

fn setup_logger(log_level: log::LevelFilter) -> Result<(), fern::InitError> {
    let dispatcher = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                time::SystemTime::now()
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap_or_else(|e| {
                        println!("Can't get time since epoch: '{}'. Using a dummy value.", e);
                        time::Duration::from_secs(0)
                    })
                    .as_secs(),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level);

    dispatcher.chain(std::io::stdout()).apply()?;

    Ok(())
}

// Wait for connections from managers on the configured interface and process `sign` messages.
fn daemon_main(
    config: Config,
    noise_privkey: &NoisePrivkey,
    bitcoin_privkey: &secp256k1::SecretKey,
) {
    let host = config.listen;
    let listener = TcpListener::bind(host).unwrap_or_else(|e| {
        log::error!("Error binding on '{}': '{}'", host, e);
        process::exit(1);
    });
    let managers_noise_pubkeys: Vec<NoisePubkey> =
        config.managers.iter().map(|m| m.noise_key).collect();

    // We expect a single connection once in a while, there is *no need* for complexity here so
    // just treat incoming connections sequentially.
    loop {
        let mut kk_stream = match revault_net::transport::KKTransport::accept(
            &listener,
            noise_privkey,
            &managers_noise_pubkeys,
        ) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Error during handshake: '{}'", e);
                continue;
            }
        };

        match kk_stream.read_req(|req_params| {
            match req_params {
                RequestParams::Sign(sign_req) => {
                    log::trace!("Decoded request: {:#?}", sign_req);

                    let res = match process_sign_message(&config, sign_req, bitcoin_privkey) {
                        Ok(res) => res,
                        Err(e) => {
                            log::error!("Error when processing 'sign' message: '{}'", e);
                            return None;
                        }
                    };
                    log::trace!("Decoded response: {:#?}", res);

                    Some(ResponseResult::SignResult(res))
                }
                _ => {
                    // FIXME: This should probably be fatal, they are violating the protocol
                    log::error!("Unexpected message: '{:?}'", req_params);
                    None
                }
            }
        }) {
            Ok(buf) => buf,
            Err(e) => {
                log::error!(
                    "Error handling request from stream '{:?}': '{}'",
                    kk_stream,
                    e
                );
                continue;
            }
        }
    }
}

fn create_datadir(datadir_path: &PathBuf) -> Result<(), std::io::Error> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).recursive(true).create(datadir_path)
}

fn main() {
    let args = env::args().collect();
    let conf_file = parse_args(args);

    let mut config = Config::from_file(conf_file).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {}", e);
        process::exit(1);
    });
    let log_level = config.log_level;
    setup_logger(log_level).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });

    if !config.data_dir.as_path().exists() {
        create_datadir(&config.data_dir).unwrap_or_else(|e| {
            eprintln!("Error creating datadir: '{}'", e);
            process::exit(1);
        })
    }
    config.data_dir = fs::canonicalize(config.data_dir).unwrap_or_else(|e| {
        eprintln!("Error creating datadir: '{}'", e);
        process::exit(1);
    });

    let mut noise_key_path = config.data_dir.clone();
    noise_key_path.push("noise_secret");
    let noise_privkey = read_or_create_noise_key(&noise_key_path).unwrap_or_else(|e| {
        eprintln!("Error reading Noise key: '{}'", e);
        process::exit(1);
    });

    let mut bitcoin_key_path = config.data_dir.clone();
    bitcoin_key_path.push("bitcoin_secret");
    let bitcoin_privkey = read_bitcoin_privkey(&bitcoin_key_path).unwrap_or_else(|e| {
        eprintln!("Error reading Bitcoin key: '{}'", e);
        process::exit(1);
    });

    let mut db_path = config.data_dir.clone();
    db_path.push("cosignerd.sqlite3");
    setup_db(&db_path).unwrap_or_else(|e| {
        eprintln!("Error setting up database: '{}'", e);
        process::exit(1);
    });

    if config.daemon {
        unsafe {
            daemonize(&config.data_dir, &config.pid_file(), &config.log_file()).unwrap_or_else(
                |e| {
                    eprintln!("Error daemonizing: {}", e);
                    // Duplicated as the error could happen after we fork and set stderr to /dev/null
                    log::error!("Error daemonizing: {}", e);
                    process::exit(1);
                },
            );
        }
    }
    let noise_pubkey =
        NoisePubkey(curve25519::scalarmult_base(&curve25519::Scalar(noise_privkey.0)).0);
    let bit_pubkey = PrivateKey {
        compressed: true,
        network: revault_tx::bitcoin::Network::Bitcoin,
        key: bitcoin_privkey,
    }
    .public_key(&secp256k1::Secp256k1::signing_only());
    log::info!(
        "Started cosignerd daemon with Noise pubkey '{}' and Bitcoin pubkey '{}'",
        noise_pubkey.0.to_hex(),
        bit_pubkey
    );

    daemon_main(config, &noise_privkey, &bitcoin_privkey);
}
