FROM lukemathwalker/cargo-chef:latest-rust-1.81 AS chef
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/bnb-chain/reth
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN rustup toolchain install nightly
RUN cargo +nightly chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN rustup toolchain install nightly
COPY --from=planner /app/recipe.json recipe.json

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE $BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS "$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES="bsc"
ENV FEATURES $FEATURES

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Builds dependencies
RUN cargo +nightly chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json --manifest-path crates/bsc/bin/Cargo.toml

# Build application
COPY . .
RUN cargo +nightly build --profile $BUILD_PROFILE --features "$FEATURES" --bin bsc-reth --manifest-path crates/bsc/bin/Cargo.toml

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/bsc-reth /app/bsc-reth

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

# Copy reth over from the build stage
COPY --from=builder /app/bsc-reth /usr/local/bin

# Copy licenses
COPY LICENSE-* ./

EXPOSE 30303 30303/udp 9001 8545 8546
ENTRYPOINT ["/usr/local/bin/bsc-reth"]