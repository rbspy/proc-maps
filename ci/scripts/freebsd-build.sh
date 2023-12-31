#!/usr/bin/env bash

set -e

source "$HOME/.cargo/env"

cd /vagrant

cargo build --no-default-features --release --workspace --all-targets
cargo test --no-default-features --release
