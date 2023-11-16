#!/usr/bin/env bash

set -e

source "$HOME/.cargo/env"

cd /vagrant

if [ -f build-artifacts.tar ]; then
  tar xf build-artifacts.tar
  rm -f build-artifacts.tar
fi

cargo build --no-default-features --release --workspace --all-targets
cargo test --no-default-features --release

tar cf build-artifacts.tar target
tar rf build-artifacts.tar .cargo/git || true
tar rf build-artifacts.tar .cargo/registry || true
