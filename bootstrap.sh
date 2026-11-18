#!/usr/bin/env bash
set -euo pipefail

ref=${VECTOR_SETUP_REF:-main}
if [[ ! $ref =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo 'VECTOR_SETUP_REF must be a branch, tag or commit without slashes.' >&2
    exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 10 --max-time 120 \
    "https://codeload.github.com/samoyed24/vector-setup/tar.gz/$ref" -o "$tmp/vector-setup.tar.gz"
tar -xzf "$tmp/vector-setup.tar.gz" --strip-components=1 -C "$tmp"

if (( $# == 0 )); then
    set -- --help
fi
bash "$tmp/vector-setup.sh" "$@"
