# WireTap eBPF toolchain image.
#
# Builds the pinned rustc fork (vadorovsky/rust @ 26afb49e7af, branch
# btf-relocations) and bpf-linker (@ a08a2f5, needs LLVM 22) that compile
# crates/hop-tap-ebpf with native #[relocatable] CO-RE. See
# docs/ebpf-toolchain.md; scripts/build-ebpf-toolchain.sh is the executable
# form of that doc and does the actual work here.
#
# CI points HOP_TAP_TOOLCHAIN_IMAGE at a build of this file and runs the eBPF
# lane inside it. Building it is heavy (the rustc bootstrap is 30-90 min and
# wants a few GB of RAM and ~30 GB of disk) so it is built rarely and cached,
# not on every push.
#
#   docker build -f docker/toolchain.Dockerfile -t wiretap-toolchain .
#   docker build -f docker/toolchain.Dockerfile --target base -t wiretap-toolchain-base .   # deps only

# --- base: system deps + LLVM 22 + rustup (fast; no rustc bootstrap) --------
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates python3 build-essential cmake pkg-config \
        ninja-build lsb-release wget software-properties-common gnupg \
    && rm -rf /var/lib/apt/lists/*

# LLVM 22 development libraries (apt.llvm.org), for bpf-linker's llvm-sys.
ARG LLVM_MAJOR=22
RUN curl -fsSL https://apt.llvm.org/llvm.sh -o /tmp/llvm.sh \
    && chmod +x /tmp/llvm.sh && /tmp/llvm.sh ${LLVM_MAJOR} \
    && apt-get update && apt-get install -y --no-install-recommends \
        llvm-${LLVM_MAJOR}-dev libpolly-${LLVM_MAJOR}-dev clang-${LLVM_MAJOR} \
    && rm -rf /var/lib/apt/lists/* /tmp/llvm.sh
ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

# rustup (a recent nightly; the build script registers the fork as stage1-vlad).
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rust-src

# --- toolchain: build the pinned rustc fork + bpf-linker --------------------
FROM base AS toolchain
WORKDIR /src
COPY scripts/build-ebpf-toolchain.sh scripts/build-ebpf-toolchain.sh
COPY docs/ebpf-toolchain.md docs/ebpf-toolchain.md
# Builds rustc (download-ci-llvm, so no LLVM source build) and bpf-linker, then
# registers the `stage1-vlad` rustup toolchain that crates/hop-tap-ebpf uses.
RUN LLVM_SYS_221_PREFIX=/usr/lib/llvm-22 \
    ./scripts/build-ebpf-toolchain.sh --work /opt/hop-tap-toolchain
# Sanity: the toolchain resolves and can see the BPF target.
RUN rustup toolchain list | grep -q stage1-vlad \
    && cargo +stage1-vlad --version
