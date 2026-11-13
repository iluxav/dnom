mod assess;
mod audit;
mod backends;
mod classify;
mod collect;
mod config;
mod decoys;
mod episode;
mod event;
mod falco;
mod notify;
mod paths;
mod policy;
mod questions;
mod redact;

use clap::{Parser, Subcommand};

/// dnom: eBPF host monitor PoC.
///
///   sudo dnom collect | dnom classify     build episodes, ask the model, apply policies
///   dnom monitor                          live threat reports (in another terminal)
///   dnom audit                            what was assessed; dnom audit <episode> for one
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// (root) Load observe-only eBPF sensors and print events as JSON lines on stdout.
    Collect,
    /// (unprivileged) Read events, build episodes, and ask a model the six questions.
    Classify(classify::ClassifyArgs),
    /// (unprivileged) The audit trail: list assessed episodes, or show one with its process tree.
    Audit(audit::AuditArgs),
    /// (unprivileged) Follow the audit trail live and show only threat reports (matched rules).
    Monitor(audit::MonitorArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Collect => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(collect::run()),
        Command::Classify(args) => classify::run(args),
        Command::Audit(args) => audit::audit(args),
        Command::Monitor(args) => audit::monitor(args),
    }
}
