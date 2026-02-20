use anyhow::Error;
use arti_client::{DataStream, TorClient};
use crossterm::terminal;
use log::{error, info, debug};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;

/// The port the server shell service listens on (matches `SHELL_PORT` in onion_server.rs).
const SHELL_PORT: u16 = 22;

/// A Tor-native shell client.
///
/// Connects to a backtor shell service running as a Tor onion service and
/// bridges the current process's terminal to the remote PTY shell, behaving
/// like a minimal SSH client that requires no key exchange because Tor's
/// end-to-end encryption and the onion address itself act as the secure
/// channel and the shared secret respectively.
pub struct OnionShellClient {
    client: TorClient<PreferredRuntime>,
}

impl OnionShellClient {
    /// Create a new client from an already-bootstrapped [`TorClient`].
    pub fn new(client: TorClient<PreferredRuntime>) -> Self {
        Self { client }
    }

    /// Connect to the shell service at `onion_host` and run an interactive
    /// session until the connection is closed from either side.
    ///
    /// `onion_host` may be supplied with or without the `.onion` suffix.
    ///
    /// The local terminal is placed in raw mode for the duration of the
    /// session so that all key-presses (including Ctrl-C, Ctrl-D, arrow keys,
    /// etc.) are forwarded verbatim to the remote PTY. The terminal is
    /// restored to its original mode when this function returns, even if an
    /// error occurs.
    pub async fn connect(&self, onion_host: &str) -> Result<(), Error> {
        // Normalise the host: ensure it ends with ".onion".
        let host = if onion_host.ends_with(".onion") {
            onion_host.to_owned()
        } else {
            format!("{onion_host}.onion")
        };

        debug!("Connecting to {host}:{SHELL_PORT} via Tor…");

        let stream: DataStream = self
            .client
            .connect((host.as_str(), SHELL_PORT))
            .await
            .map_err(|e| anyhow::anyhow!("Tor connect failed: {e}"))?;

        debug!("Connected to {host}. Starting shell session.");

        // Print a short banner before entering raw mode so it ends up with
        // normal line endings.
        info!("Connected. Press Ctrl-D to end the session.");

        // Enter raw mode: the local terminal will no longer do any local
        // processing – every byte from stdin goes straight to the network.
        terminal::enable_raw_mode()?;

        // Drive the session and capture any error so we can clean up first.
        let result = self.run_session(stream).await;

        // Always restore the terminal, regardless of how the session ended.
        let _ = terminal::disable_raw_mode();

        // Print with explicit CR so the line starts at column 0 even though
        // we just left raw mode.
        info!("\r\nSession closed.");

        result
    }

    /// Internal: run the bidirectional copy loop between the local terminal
    /// and the Tor `DataStream`.
    ///
    /// Returns when either the server closes the connection or stdin reaches
    /// EOF (Ctrl-D).
    async fn run_session(&self, stream: DataStream) -> Result<(), Error> {
        // DataStream implements futures::io::AsyncRead + AsyncWrite.
        // Wrap it with the tokio-util compat layer so we can use the tokio
        // AsyncRead / AsyncWrite traits and tokio::io::split.
        let compat = stream.compat();
        let (mut net_read, mut net_write) = tokio::io::split(compat);

        // ── stdin → network ─────────────────────────────────────────────────
        //
        // tokio::io::stdin() is backed by epoll on Linux, so the in-flight
        // read future is truly cancellable via JoinHandle::abort(). This
        // avoids the process hanging on a spawn_blocking thread that is stuck
        // in a blocking stdin.read() call after the server closes the
        // connection.
        let mut stdin_to_net = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 256];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // In raw mode Ctrl-D is sent as byte 0x04; treat it as a local
                        // escape to end the session without forwarding it.
                        if buf[..n].contains(&0x04) {
                            break;
                        }

                        if net_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if net_write.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            debug!("stdin→net task finished");
        });

        // ── network → stdout ────────────────────────────────────────────────
        //
        // The remote PTY already handles CRLF translation, so we write the
        // bytes verbatim to stdout.
        let mut net_to_stdout = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            let mut buf = [0u8; 4096];
            loop {
                match net_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdout.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if stdout.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            debug!("net→stdout task finished");
        });


        tokio::select! {
            res = &mut stdin_to_net => {
                net_to_stdout.abort();
                if let Err(e) = res {
                    error!("stdin→net task panicked: {e}");
                }
            }
            res = &mut net_to_stdout => {
                stdin_to_net.abort();
                if let Err(e) = res {
                    error!("net→stdout task panicked: {e}");
                }
            }
        }

        Ok(())
    }
}
