FROM rust:1.95-bookworm AS build
RUN sed -i s,http://deb.debian.org,https://deb.debian.org,g /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update && apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,id=rpl-cargo-registry,target=/usr/local/cargo/registry cargo fetch --locked --target="$(rustc -vV | sed -n 's/^host: //p')"
COPY src ./src
RUN --mount=type=cache,id=rpl-cargo-registry,target=/usr/local/cargo/registry cargo build --release --locked
FROM build AS test
RUN --mount=type=cache,id=rpl-cargo-registry,target=/usr/local/cargo/registry cargo test --locked
FROM debian:bookworm-slim AS runtime
RUN apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 install -y --no-install-recommends libpcap0.8 tzdata ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /work/target/release/rust-pcap-log /usr/local/bin/rust-pcap-log
ENV TZ=UTC
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rust-pcap-log"]
