#!/bin/bash

#
# TTP: Tiny TLS Proxy: a very simple TLS proxy server with
#                      focus on resource consumption.
#
# Made by Davidson Francis.
# This is free and unencumbered software released into the public domain.
#

set -e

# Backup current folder
pushd .
export CURDIR="$( cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$CURDIR/"
export PATH="$PATH:$CURDIR/armv6-linux-musleabi-cross/bin"
export MUSL_PREFIX="$CURDIR/armv6-linux-musleabi-cross/armv6-linux-musleabi"

# Misc
MUSL_ARMv6_LINK="https://musl.cc/armv6-linux-musleabi-cross.tgz"
BEARSSL_HASH="3c040368f6791553610e362401db1efff4b4c5b8"

download_musl_armv6() {
	echo "[+] Downloading musl ..."
	wget "$MUSL_ARMv6_LINK" -O armv6-musl.tgz
	tar xvf armv6-musl.tgz
	popd
}

# This is slightly better than using the CI file
# because our env vars are already set!
build_ttp_armv6() {
	popd
	echo "[+] Building TTP!"
	CC=armv6-linux-musleabi-gcc make -j4
	echo "[+] File type:"
	file ttp
	echo "[+] File size before strip:"
	ls -lah ttp
	echo "[+] Stripping TTP..."
	armv6-linux-musleabi-strip --strip-all ttp
	echo "[+] File size *after* strip:"
	ls -lah ttp
	echo "[+] File hash:"
	sha256sum ttp
}

# Dispatcher
if [ "$1" == "download_musl_armv6" ]; then
	download_musl_armv6
elif [ "$1" == "build_ttp_armv6" ]; then
	build_ttp_armv6
else
	echo "No option found!"
	exit 1
fi
