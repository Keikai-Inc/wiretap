//! Cross-compiles the kernel-side `hop-tap-ebpf` crate as part of the
//! userspace daemon build.
//!
//! The eBPF crate needs a pinned rustc fork that supports
//! `#[relocatable]` (native CO-RE field-offset relocations), registered
//! as the rustup toolchain `stage1-vlad`. `docs/ebpf-toolchain.md` has
//! the exact commits and `scripts/build-ebpf-toolchain.sh` builds it.
//! The toolchain name is overridable via `HOP_TAP_BPF_TOOLCHAIN`, and
//! `HOP_TAP_SKIP_EBPF_BUILD=1` embeds a prebuilt object (each release
//! publishes the one it shipped as `hop-tap-ebpf`).
//!
//! Gated on `cfg(target_os = "linux")` so the workspace still resolves
//! and builds (sans bytecode) on macOS dev machines. The userspace
//! `run()` is also Linux-gated, so the macOS build produces a daemon
//! binary that immediately reports "linux only" and exits.

fn main() {
    println!("cargo:rerun-if-env-changed=HOP_TAP_BPF_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=HOP_TAP_SKIP_EBPF_BUILD");

    #[cfg(target_os = "linux")]
    build_ebpf();
}

#[cfg(target_os = "linux")]
fn build_ebpf() {
    use std::{env, path::PathBuf, process::Command};

    if env::var_os("HOP_TAP_SKIP_EBPF_BUILD").is_some() {
        // Escape hatch: rust-analyzer / docs.rs / CI lanes that don't
        // have the cross-toolchain installed.
        println!("cargo:warning=HOP_TAP_SKIP_EBPF_BUILD set, skipping eBPF cross-build");
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ebpf_crate = manifest_dir
        .parent()
        .expect("crates/")
        .join("hop-tap-ebpf");

    println!("cargo:rerun-if-changed={}", ebpf_crate.display());

    let toolchain =
        env::var("HOP_TAP_BPF_TOOLCHAIN").unwrap_or_else(|_| "stage1-vlad".to_string());

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb-unknown-none",
        _ => "bpfel-unknown-none",
    };

    // Always build the ebpf crate in release mode — debug builds for
    // bpfel-unknown-none routinely produce instructions the verifier
    // rejects (excessive stack usage, non-inlined helpers).
    let args: Vec<String> = vec![
        format!("+{}", toolchain),
        "build".into(),
        "--release".into(),
        format!("--target={}", target),
        "-Z".into(),
        "build-std=core".into(),
    ];

    let path = env::var("PATH").expect("PATH");
    let home = env::var("HOME").expect("HOME");
    let cargo_home = env::var("CARGO_HOME").unwrap_or_else(|_| format!("{}/.cargo", home));
    let rustup_home =
        env::var("RUSTUP_HOME").unwrap_or_else(|_| format!("{}/.rustup", home));

    let mut cmd = Command::new("cargo");
    // env_clear() so the inherited CARGO_*_TARGET / RUSTFLAGS from the
    // outer userspace build don't leak into the cross-build and
    // confuse cargo's target resolution.
    cmd.current_dir(&ebpf_crate)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTUP_HOME", rustup_home);

    if let Ok(ld) = env::var("LD_LIBRARY_PATH") {
        cmd.env("LD_LIBRARY_PATH", ld);
    }

    let status = cmd
        .args(args.iter().map(String::as_str))
        .env(
            "RUSTFLAGS",
            "-C debuginfo=2 -C link-arg=--btf -Z macro-backtrace",
        )
        .status()
        .expect("failed to spawn `cargo` for hop-tap-ebpf");

    if !status.success() {
        panic!("hop-tap-ebpf cross-build failed: {}", status);
    }
}
