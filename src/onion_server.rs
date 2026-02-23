use arti_client::TorClient;
use futures::{Stream, StreamExt};
use log::{error, info, debug};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use safelog::DisplayRedacted;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_proto::client::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;
use tor_rtcompat::SpawnExt;

use crate::utils;
use crate::utils::get_onion_address;
use tor_hsrproxy::{
    OnionServiceReverseProxy,
    config::{Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr},
};

// The port on which the shell service listens (telnet-like)
const SHELL_PORT: u16 = 23;

type RunningOnionServices = HashMap<String, CancellationToken>;

pub(crate) static RUNNING_ONION_SERVICES: LazyLock<Arc<Mutex<RunningOnionServices>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Returns the path to the user's login shell.
///
/// On Unix, reads the `$SHELL` environment variable, falling back to
/// `/etc/passwd` for the current UID, then `/bin/sh` as a last resort.
///
/// On Windows, prefers PowerShell if available, otherwise falls back to
/// `cmd.exe`.
fn get_login_shell() -> String {
    #[cfg(unix)]
    {
        // First try $SHELL
        if let Ok(shell) = std::env::var("SHELL") {
            if !shell.is_empty() {
                return shell;
            }
        }

        // Fall back to parsing /etc/passwd for the current user's login shell
        let uid = unsafe { libc::getuid() };
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 7 {
                    if let Ok(entry_uid) = fields[2].parse::<u32>() {
                        if entry_uid == uid {
                            let shell = fields[6].trim();
                            if !shell.is_empty() {
                                return shell.to_string();
                            }
                        }
                    }
                }
            }
        }

        "/bin/sh".to_string()
    }

    #[cfg(windows)]
    {
        let ps_path =
            std::path::Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        if ps_path.exists() {
            return ps_path.to_string_lossy().into_owned();
        }

        let ps5_path = std::path::Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
        if ps5_path.exists() {
            return ps5_path.to_string_lossy().into_owned();
        }

        "cmd.exe".to_string()
    }
}

/// Spawns a login shell inside a PTY and bridges its I/O to the provided
/// async stream (the Tor onion-service data stream).
///
/// The function returns once either side closes the connection.
async fn handle_shell_connection<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let shell = get_login_shell();
    debug!("Incoming shell connection – spawning: {shell}");

    // Open a PTY pair.
    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to open PTY: {e}");
            return;
        }
    };

    // Spawn the shell attached to the PTY slave.
    let cmd = CommandBuilder::new(&shell);
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn '{shell}': {e}");
            return;
        }
    };

    // Drop the slave end in this process so only the child holds it open.
    // When the child exits the master reads will return EOF.
    drop(pair.slave);

    // Obtain synchronous reader/writer for the PTY master.
    let mut pty_reader: Box<dyn Read + Send> = match pair.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to clone PTY reader: {e}");
            let _ = child.kill();
            return;
        }
    };
    let mut pty_writer: Box<dyn Write + Send> = match pair.master.take_writer() {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to take PTY writer: {e}");
            let _ = child.kill();
            return;
        }
    };

    // Channels used to bridge the sync PTY world and the async Tor stream.
    // pty_out  : PTY master → Tor stream
    // stream_in: Tor stream → PTY master
    let (pty_out_tx, mut pty_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (stream_in_tx, mut stream_in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Blocking task: read bytes from the PTY master and forward them through
    // the channel to the async writer task below.
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if pty_out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
        debug!("PTY reader task finished");
    });

    // Blocking task: receive bytes from the async reader task and write them
    // into the PTY master (i.e. deliver them as keyboard input to the shell).
    tokio::task::spawn_blocking(move || {
        while let Some(data) = stream_in_rx.blocking_recv() {
            if pty_writer.write_all(&data).is_err() {
                break;
            }
            let _ = pty_writer.flush();
        }
        debug!("PTY writer task finished");
    });

    let (mut stream_read, mut stream_write) = tokio::io::split(stream);

    // Async task: read from the Tor stream and forward to the PTY writer task.
    let mut stream_to_pty = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stream_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream_in_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
        debug!("Stream→PTY task finished");
    });

    // Async task: receive from the PTY reader task and write to the Tor stream.
    let mut pty_to_stream = tokio::spawn(async move {
        while let Some(data) = pty_out_rx.recv().await {
            if stream_write.write_all(&data).await.is_err() {
                break;
            }
            if stream_write.flush().await.is_err() {
                break;
            }
        }
        debug!("PTY→stream task finished");
    });

    // Wait for both directions to close, then clean up the child process.
    tokio::select! {
        res = &mut pty_to_stream => {
            stream_to_pty.abort();
            if let Err(e) = res {
                error!("Stream→PTY task panicked: {e}");
            }
        }
        res = &mut stream_to_pty => {
            pty_to_stream.abort();
            if let Err(e) = res {
                error!("PTY→stream task panicked: {e}");
            }
        }
    }

    // Best-effort: kill the shell if it is still running.
    let _ = child.kill();
    debug!("Shell connection closed");
}

/// Starts a Tor onion service that gives remote callers an interactive shell.
///
/// Connections arrive on [`SHELL_PORT`] (22). Each connection is handed a
/// freshly-spawned login shell through a PTY, making the service behave like a
/// stripped-down, Tor-native SSH replacement.
///
/// If `forward_proxy` is supplied the onion service is instead wired up to an
/// existing local TCP listener via [`OnionServiceReverseProxy`], which is
/// useful for tunnelling an actual SSH daemon (or any other service).
///
/// The onion address is printed to stdout once the service is fully reachable.
pub(crate) async fn onion_service_from_sk(
    tor_client: TorClient<PreferredRuntime>,
    secret_key: Option<[u8; 32]>,
    forward_proxy: Option<(u16, SocketAddr)>,
) {
    let nickname = if let Some(sk) = secret_key {
        format!(
            "backtor-shell-{}",
            get_onion_address(utils::keypair_from_sk(sk).public().as_bytes())
        )
    } else {
        "backtor-shell".into()
    };

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse().unwrap())
        .build()
        .unwrap();

    let (onion_service, request_stream): (
        _,
        Pin<Box<dyn Stream<Item = tor_hsservice::RendRequest> + Send>>,
    ) = if secret_key.is_none() {
        match tor_client
            .launch_onion_service(svc_cfg)
            .expect("error creating onion service")
        {
            Some((service, stream)) => (service, Box::pin(stream)),
            None => {
                panic!("Failed to launch onion service");
            }
        }
    } else {
        let sk = secret_key.unwrap();
        let expanded_key_pair = utils::keypair_from_sk(sk);
        let encodable_key = tor_hscrypto::pk::HsIdKeypair::from(expanded_key_pair);

        match tor_client
            .launch_onion_service_with_hsid(svc_cfg.clone(), encodable_key)
            .expect("error creating onion service")
        {
            Some((service, stream)) => (service, Box::pin(stream)),
            None => {
                // Key already registered – reuse the existing slot.
                match tor_client
                    .launch_onion_service(svc_cfg)
                    .expect("error creating onion service")
                {
                    Some((service, stream)) => (service, Box::pin(stream)),
                    None => {
                        panic!("Failed to launch onion service");
                    }
                }
            }
        }
    };

    debug!("Onion service status: {:?}", onion_service.status());
    let clone_onion_service = onion_service.clone();

    // Announce the onion address as soon as the service is fully reachable.
    let _ = tor_client.clone().runtime().spawn(async move {
        while let Some(event) = clone_onion_service.status_events().next().await {
            if event.state().is_fully_reachable() {
                break;
            }
        }
        info!(
            "Shell service available at: {}:{}",
            clone_onion_service
                .onion_address()
                .unwrap()
                .display_unredacted(),
            SHELL_PORT,
        );
        debug!(
            "Onion service fully reachable: {:?}",
            clone_onion_service.status()
        );
    });

    let _ = tor_client.clone().runtime().spawn(async move {
        let cancel_token = CancellationToken::new();

        // Register the cancellation token so callers can stop the service.
        {
            let mut running = RUNNING_ONION_SERVICES.lock().unwrap();
            running.insert(
                onion_service
                    .onion_address()
                    .unwrap()
                    .display_unredacted()
                    .to_string()
                    .trim_end_matches(".onion")
                    .to_owned(),
                cancel_token.clone(),
            );
        }

        if let Some((local_port, target_addr)) = forward_proxy {
            // ----------------------------------------------------------------
            // Forward mode: proxy onion-service traffic to a local TCP socket.
            // Useful for tunnelling a real SSH daemon.
            // ----------------------------------------------------------------
            let proxy_rule = ProxyRule::new(
                ProxyPattern::one_port(local_port)
                    .map_err(|e| error!("Invalid port: {e}"))
                    .unwrap(),
                ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(target_addr)),
            );

            let mut proxy_config = ProxyConfigBuilder::default();
            proxy_config.set_proxy_ports(vec![proxy_rule]);
            let proxy = OnionServiceReverseProxy::new(
                proxy_config.build().expect("proxy config incomplete"),
            );

            tokio::select! {
                result = proxy.handle_requests(
                    tor_client.runtime().clone(),
                    nickname.parse().unwrap(),
                    request_stream,
                ) => {
                    match result {
                        Ok(()) => debug!("Reverse proxy finished normally"),
                        Err(e) => error!("Reverse proxy error: {e}"),
                    }
                }
                () = cancel_token.cancelled() => {
                    debug!("Onion service cancelled via token (forward mode)");
                }
            }
        } else {
            // ----------------------------------------------------------------
            // Direct shell mode: accept connections and spawn a PTY shell for
            // each one.
            // ----------------------------------------------------------------
            let accepted_streams = tor_hsservice::handle_rend_requests(request_stream);
            tokio::pin!(accepted_streams);

            loop {
                tokio::select! {
                    Some(stream_request) = accepted_streams.next() => {
                        let request = stream_request.request().clone();
                        match request {
                            IncomingStreamRequest::Begin(begin)
                                if begin.port() == SHELL_PORT =>
                            {
                                debug!("Accepting shell connection on port {SHELL_PORT}");
                                match stream_request.accept(Connected::new_empty()).await {
                                    Ok(data_stream) => {
                                        // Bridge futures-style async I/O (arti DataStream)
                                        // to tokio-style async I/O expected by our handler.
                                        let compat_stream = data_stream.compat();
                                        tokio::spawn(handle_shell_connection(compat_stream));
                                    }
                                    Err(e) => {
                                        error!("Failed to accept stream: {e}");
                                    }
                                }
                            }
                            _ => {
                                debug!(
                                    "Rejecting stream request for unexpected port/type"
                                );
                                stream_request.shutdown_circuit().unwrap_or_else(|e| {
                                    error!("Error shutting down circuit: {e}");
                                });
                            }
                        }
                    }
                    () = cancel_token.cancelled() => {
                        debug!("Onion service shutting down");
                        return;
                    }
                }
            }
        }
    });
}
