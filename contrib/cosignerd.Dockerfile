FROM rust:alpine

# Space separated list of managers' noise keys. Must be set at startup, that's a dummy key.
ENV MANAGERS_NOISE_KEYS="b28cf2091bbbecf347d29420f884a936713e7b2e86fe4f6653d7e12356d26114"
# Bitcoin and Noise private keys
ENV BITCOIN_SECRET="\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x42"
ENV NOISE_SECRET="\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x42"
# Other config options
ENV LOG_LEVEL="trace"


COPY . /srv/cosignerd/src
RUN apk add g++ make && \
    cd /srv/cosignerd/src && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build

EXPOSE 8383/tcp

CMD echo "daemon = false" >> /srv/cosignerd/config.toml && \
    echo "data_dir = '/srv/cosignerd/datadir'" >> /srv/cosignerd/config.toml && \
    echo "log_level = '$LOG_LEVEL'" >> /srv/cosignerd/config.toml && \
    for key in $MANAGERS_NOISE_KEYS; do \
        echo "[[managers]]" >> /srv/cosignerd/config.toml && \
        echo "noise_key = \"$key\"" >> /srv/cosignerd/config.toml \
    ; done && \
    mkdir /srv/cosignerd/datadir && \
    printf $BITCOIN_SECRET > /srv/cosignerd/datadir/bitcoin_secret && \
    printf $NOISE_SECRET > /srv/cosignerd/datadir/noise_secret && \
    /srv/cosignerd/src/target/debug/cosignerd --conf /srv/cosignerd/config.toml
