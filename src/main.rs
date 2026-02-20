mod onion_client;
mod onion_server;
mod utils;

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use clap::{Parser, Subcommand};
use log::debug;
use onion_client::OnionShellClient;
use onion_server::onion_service_from_sk;
use tor_rtcompat::PreferredRuntime;

/// backtor – a Tor-native remote shell.
///
/// Run without arguments (or with `serve`) to expose your local shell as a
/// hidden service. Run with `connect <address>` to attach to a remote shell.
#[derive(Debug, Parser)]
#[command(name = "backtor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose the local shell as a Tor onion service (default when no subcommand is given).
    Serve {
        /// A 32-byte hex secret key used to derive a stable onion address.
        /// If omitted a fresh ephemeral address is generated each run.
        #[arg(short, long, value_name = "HEX")]
        key: Option<String>,
    },

    /// Connect to a backtor shell service.
    Connect {
        /// The onion address to connect to (with or without the .onion suffix).
        address: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    // Default to serve mode when no subcommand is given.
    let command = cli.command.unwrap_or(Command::Serve { key: None });

    debug!("Bootstrapping Tor – this may take a moment…");

    let config = TorClientConfig::default();
    let tor_client = TorClient::<PreferredRuntime>::create_bootstrapped(config).await?;

    debug!("Tor bootstrapped.");

    match command {
        // ── Server mode ───────────────────────────────────────────────────────
        Command::Serve { key } => {
            let secret_key: Option<[u8; 32]> = match key {
                Some(hex) => {
                    let bytes = hex::decode(&hex)
                        .map_err(|e| anyhow::anyhow!("Invalid hex key: {e}"))?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Key must be exactly 32 bytes (64 hex chars)"))?;
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
        Command::Connect { address } => {
            debug!("Connecting to {address}…");
            OnionShellClient::new(tor_client)
                .connect(&address)
                .await?;
        }
    }

    Ok(())
}
