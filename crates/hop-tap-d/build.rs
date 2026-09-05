//! Provides the kernel-side eBPF object the daemon embeds.
//!
//! Two sources, in order of preference:
//!   1. A fresh cross-build of the `hop-tap-ebpf` crate, when this is a dev
//!      checkout on Linux with the pinned rustc fork (`stage1-vlad`, overridable
//!      via `HOP_TAP_BPF_TOOLCHAIN`) installed and `HOP_TAP_SKIP_EBPF_BUILD` is
//!      unset. The fork implements `#[relocatable]` CO-RE; see
//!      `docs/ebpf-toolchain.md` / `scripts/build-ebpf-toolchain.sh`.
//!   2. Otherwise the committed relocatable object at
//!      `ebpf/hop-tap-ebpf.bpf.o`. This is what published crates, `cargo
//!      install`, docs.rs and contributors without the fork use. The object is
//!      CO-RE bytecode, so one file runs across kernels and architectures.
//!
//! Either way the chosen object is written to `$OUT_DIR/hop-tap-ebpf`, which
//! `main.rs` embeds with `include_bytes_aligned!`.

use std::{env, fs, path::Path, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=HOP_TAP_BPF_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=HOP_TAP_SKIP_EBPF_BUILD");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out.join("hop-tap-ebpf");
    let prebuilt = manifest.join("ebpf/hop-tap-ebpf.bpf.o");
    println!("cargo:rerun-if-changed={}", prebuilt.display());

    if build_from_source(&manifest, &dest) {
        return;
    }
    if prebuilt.exists() {
        fs::copy(&prebuilt, &dest).expect("copy committed eBPF object to OUT_DIR");
        return;
    }
    panic!(
        "no eBPF object available: source build was skipped or unavailable and \
         there is no committed object at {}. See docs/ebpf-toolchain.md.",
        prebuilt.display()
    );
}

/// Cross-build the `hop-tap-ebpf` crate when we're a dev checkout on Linux with
/// the pinned toolchain. Returns false (fall back to the committed object) when
/// skipped, off-Linux, the source crate is absent (published crate), or the
/// toolchain isn't installed. Panics if a build we *did* start fails.
fn build_from_source(manifest: &Path, dest: &Path) -> bool {
    if cfg!(not(target_os = "linux")) {
        return false;
    }
    if env::var_os("HOP_TAP_SKIP_EBPF_BUILD").is_some() {
        return false;
    }
    let ebpf_crate = manifest.parent().expect("crates/").join("hop-tap-ebpf");
    if !ebpf_crate.join("Cargo.toml").exists() {
        return false; // published crate: no eBPF source, use the committed object
    }
    let toolchain = env::var("HOP_TAP_BPF_TOOLCHAIN").unwrap_or_else(|_| "stage1-vlad".to_string());
    if !toolchain_installed(&toolchain) {
        println!(
            "cargo:warning=eBPF toolchain '{toolchain}' not installed; using the committed object"
        );
        return false;
    }

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };
    let home = env::var("HOME").expect("HOME");
    let status = Command::new("cargo")
        .current_dir(&ebpf_crate)
        // env_clear so the outer build's CARGO_*_TARGET / RUSTFLAGS don't leak in.
        .env_clear()
        .env("PATH", env::var("PATH").expect("PATH"))
        .env("HOME", &home)
        .env("CARGO_HOME", env::var("CARGO_HOME").unwrap_or_else(|_| format!("{home}/.cargo")))
        .env("RUSTUP_HOME", env::var("RUSTUP_HOME").unwrap_or_else(|_| format!("{home}/.rustup")))
        .env("RUSTFLAGS", "-C debuginfo=2 -C link-arg=--btf -Z macro-backtrace")
        .args([
            &format!("+{toolchain}"),
            "build",
            "--release",
            &format!("--target={target}"),
            "-Z",
            "build-std=core",
        ])
        .status()
        .expect("failed to spawn `cargo` for hop-tap-ebpf");
    if !status.success() {
        panic!("hop-tap-ebpf cross-build failed: {status}");
    }
    let built = ebpf_crate.join(format!("target/{target}/release/hop-tap-ebpf"));
    fs::copy(&built, dest).expect("copy freshly built eBPF object to OUT_DIR");
    true
}

fn toolchain_installed(name: &str) -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.starts_with(name)))
        .unwrap_or(false)
}
