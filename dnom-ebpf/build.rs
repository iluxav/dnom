use which::which;

/// Rebuild the eBPF crate when the `bpf-linker` binary changes (copied from aya-template).
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
