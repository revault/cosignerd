# Cosignerd

The anti-replay oracle used under the [Revault architecture](https://github.com/revault/practical-revault/blob/master/revault.pdf).

## Usage

`cosignerd` must be used along with `revaultd`. Check `revaultd's` [tutorial](https://github.com/revault/revaultd/tree/master/doc/USAGE.md) to get started!

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

## Licence

BSD 3-clauses, see [LICENSE](LICENSE).
