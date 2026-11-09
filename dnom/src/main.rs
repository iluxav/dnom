mod assess;
mod classify;
mod collect;
mod config;
mod episode;
mod event;
mod paths;
mod redact;

use clap::{Parser, Subcommand};

/// dnom: eBPF host monitor PoC.
///
///   sudo dnom collect | dnom classify --backend local
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Collect => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(collect::run()),
        Command::Classify(args) => classify::run(args),
    }
}
