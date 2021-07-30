# Cosignerd

The anti-replay oracle used under the [Revault architecture](https://github.com/revault/practical-revault/blob/master/revault.pdf).

## Usage
`cosignerd` must be used along with `revaultd`. Check `revaultd's` [tutorial](https://github.com/revault/revaultd/tree/master/doc/USAGE.md) to get started!

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
