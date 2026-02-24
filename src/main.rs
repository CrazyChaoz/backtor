#[cfg(feature = "client")]
mod onion_client;
#[cfg(feature = "server")]
mod onion_server;
mod utils;

use anyhow::Result;
use arti_client::{TorClient, config::TorClientConfigBuilder};
use clap::{Parser, Subcommand};
use log::debug;
#[cfg(feature = "client")]
use onion_client::OnionShellClient;
#[cfg(feature = "server")]
use onion_server::onion_service_from_sk;
use tor_rtcompat::PreferredRuntime;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    prelude::*,
};

/// backtor – a Tor-native remote shell.
///
/// Run without arguments (or with `serve`) to expose your local shell as a
/// hidden service. Run with `connect <address>` to attach to a remote shell.
#[derive(Debug, Parser)]
#[command(name = "backtor", version, about, long_about = None)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count, help = "Increase verbosity level")]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose the local shell as a Tor onion service (default when no subcommand is given).
    #[cfg(feature = "server")]
    Serve {
        /// A 32-byte hex secret key used to derive a stable onion address.
        /// If omitted a fresh ephemeral address is generated each run.
        #[arg(short, long, value_name = "HEX")]
        key: Option<String>,
    },

    /// Connect to a backtor shell service.
    #[cfg(feature = "client")]
    Connect {
        /// The onion address to connect to (with or without the .onion suffix).
        address: String,
    },
}

fn init_logging(cli_loglevel: u8) {
    // Start with: default=info, arti crates=error

    let log_level = match cli_loglevel {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let mut filter = EnvFilter::builder()
        .parse_lossy(format!("backtor={log_level},arti_client=error,tor_hsservice=error,tor_dirmgr=error,tor_guardmgr=error,tor_circmgr=error"));

    // If ARTI_LOG is set, override the arti crate levels with whatever it says.
    // e.g. ARTI_LOG=debug  → sets both arti crates to debug
    // e.g. ARTI_LOG=arti_client=warn,tor_stuff=trace  → fine-grained control
    if let Ok(arti_log) = std::env::var("ARTI_LOG") {
        for directive in arti_log.split(',') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            // If it's a bare level like "debug", apply it to all arti crates
            if let Ok(level) = directive.parse::<LevelFilter>() {
                filter = filter
                    .add_directive(format!("arti_client={level}").parse().unwrap())
                    .add_directive(format!("tor_hsservice={level}").parse().unwrap())
                    .add_directive(format!("tor_dirmgr={level}").parse().unwrap())
                    .add_directive(format!("tor_guardmgr={level}").parse().unwrap())
                    .add_directive(format!("tor_circmgr={level}").parse().unwrap());
            } else {
                // Otherwise treat it as a full directive like "arti_client=warn"
                if let Ok(d) = directive.parse() {
                    filter = filter.add_directive(d);
                }
            }
        }
    }

    // Also respect RUST_LOG for your own crate's level, if set.
    // Directives added later override earlier ones for the same target,
    // so RUST_LOG can still override everything if you want.
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        for directive in rust_log.split(',') {
            if let Ok(d) = directive.trim().parse() {
                filter = filter.add_directive(d);
            }
        }
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    init_logging(cli.verbose);

    // Default to serve mode when no subcommand is given.
    let command = cli.command.unwrap_or(Command::Serve { key: None });

    debug!("Bootstrapping Tor – this may take a moment…");
    
    let current_directory = std::env::current_dir().expect("failed to determine current directory");
    
    let mut cfg_builder = TorClientConfigBuilder::from_directories(
        current_directory.join(".backtor").join("config"),
        current_directory.join(".backtor").join("cache"),
    );
    cfg_builder.storage().permissions().dangerously_trust_everyone();
    let cfg = cfg_builder.build()?;
    let tor_client = TorClient::<PreferredRuntime>::create_bootstrapped(cfg).await?;

    debug!("Tor bootstrapped.");

    match command {
        // ── Server mode ───────────────────────────────────────────────────────
        #[cfg(feature = "server")]
        Command::Serve { key } => {
            let secret_key: Option<[u8; 32]> = match key {
                Some(hex) => {
                    let bytes =
                        hex::decode(&hex).map_err(|e| anyhow::anyhow!("Invalid hex key: {e}"))?;
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                        anyhow::anyhow!("Key must be exactly 32 bytes (64 hex chars)")
                    })?;
                    Some(arr)
                }
                None => None,
            };

            debug!("Starting shell service…");
            onion_service_from_sk(tor_client, secret_key, None).await;

            // Park the main task; the service runs on spawned tasks.
            std::future::pending::<()>().await;
        }

        // ── Client mode ───────────────────────────────────────────────────────
        #[cfg(feature = "client")]
        Command::Connect { address } => {
            debug!("Connecting to {address}…");
            OnionShellClient::new(tor_client).connect(&address).await?;
        }
    }

    Ok(())
}
