# Cosignerd

The anti-replay oracle used under the [Revault architecture](https://github.com/revault/practical-revault/blob/master/revault.pdf).

## Usage

`cosignerd` must be used along with `revaultd` as part of a Revault deployment.
If you are looking for trying out Revault, check out the [`aquarium`](https://github.com/revault/aquarium)
(a script putting all the Revault parts together on a regtest network).

## Testing

Unit tests can be run using the command
```
cargo test
```

You'll need [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs) for running fuzz tests.

```
cd fuzz/ && cargo hfuzz run process_sign_message
```

Alternatively you can clone the existing corpus for the `process_sign_message` target and start extending it from there. For example:

```
# Still from the root of the fuzz/ directory
git clone https://github.com/revault/cosignerd_fuzz_corpus
HFUZZ_RUN_ARGS="--exit_upon_crash -v --input cosignerd_fuzz_corpus" cargo hfuzz run process_sign_message
```

Refer to [Honggfuzz's doc](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md#cmdline---help) for more run options.

You can build it like any other Rust project, using Cargo:
```
git clone https://github.com/revault/cosignerd
cd cosignerd && cargo build
```

You'll need a configuration file to start it. You can find an example at
[`contrib/config.toml`](contrib/config.toml):
```
cargo run -- --conf ./contrib/config.toml
```

For testing purpose and/or running `cosignerd` on a non-UNIX system you can use Docker:
```
# From the root of the repository
docker build -t cosignerd -f contrib/cosignerd.Dockerfile .
docker run --rm --name cosignerd cosignerd
```
The configuration is here passed through environment variables:
```
docker run -it --rm --name cosignerd -e NOISE_SECRET="\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" -e BITCOIN_SECRET="\x43\xff\x32\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\81\x01" -e MANAGERS_NOISE_KEYS="e798cf79e7245f06f62cc76609d51c76d42f3da4fab831f543f3254e5c6d7dc7 a19052df1337936e549a6b830ff4cc0e9028eaf6e79779de76d200e3b201953b cebbe8b9edadab14f23dbe1f4f0d55c7a3e9de13ab9adbe4aefacdc26f7c7dd1" -e LOG_LEVEL="debug" cosignerd
```

## Licence

BSD 3-clauses, see [LICENSE](LICENSE).
