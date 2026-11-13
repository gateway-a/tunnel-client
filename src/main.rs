use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

fn verbose() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("TUNNEL_VERBOSE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

macro_rules! vlog {
    ($($arg:tt)*) => { if verbose() { eprintln!($($arg)*); } };
}

// --- Frame encryption ---


struct FrameCrypto {
    key: [u8; 32],
}

impl FrameCrypto {
    fn from_token(token: &str) -> Result<Self, String> {
        use hmac::Mac;
        let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(token.as_bytes())
            .map_err(|e| format!("frame key init: {}", e))?;
        mac.update(FRAME_KEY_LABEL);
        let derived = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(Self { key })
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
        // The key is derived from the shared token, so every frame MUST use a
        // fresh random nonce or ChaCha20-Poly1305 breaks (nonce reuse leaks
        // plaintext + allows tag forgery). The nonce travels in the frame, so
        // the peer reads it back — no shared counter state needed.
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).expect("csprng");

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&self.key));
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

        let mut buf = data.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce, &[], &mut buf).expect("encrypt");

        let mut out = Vec::with_capacity(12 + buf.len() + 16);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        out
    }

    fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
        if data.len() < 28 { return None; }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&data[0..4]);
        nonce_bytes[4..12].copy_from_slice(&data[4..12]);

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&self.key));
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

        let tag_start = data.len() - 16;
        let mut buf = data[12..tag_start].to_vec();
        let tag = chacha20poly1305::Tag::from_slice(&data[tag_start..]);

        cipher.decrypt_in_place_detached(&nonce, &[], &mut buf, tag).ok()?;
        Some(buf)
    }
}

// --- Frame protocol (same as server) ---

const FRAME_AUTH: u8 = 0x01;
const FRAME_AUTH_OK: u8 = 0x02;
const FRAME_AUTH_ERR: u8 = 0x03;
const FRAME_OPEN: u8 = 0x04;
const FRAME_DATA: u8 = 0x05;
const FRAME_CLOSE: u8 = 0x06;
const FRAME_PING: u8 = 0x07;
const FRAME_PONG: u8 = 0x08;

const FRAME_HEADER_LEN: usize = 9;
const READ_BUF_SIZE: usize = 65536;
const RECONNECT_BASE_MS: u64 = 1000;
const RECONNECT_MAX_MS: u64 = 30000;
/// A tunnel that was just created (or recreated under the same name) is live
/// on the gateway only after its next config reload, a few seconds later; an
/// auth reject in that window is expected and retried at once rather than
/// backed off.
const FRESH_AUTH_WINDOW: Duration = Duration::from_secs(15);
const FRESH_AUTH_RETRY_MS: u64 = 1000;
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the TLS loop will sit in a read before looking at what it has to
/// write. It cannot use a second thread — a TLS stream is not clonable — so
/// this is what bounds the delay between a backend answering and the answer
/// leaving. Left blocking, the loop only woke on the server's 5-second ping and
/// every response inherited a wait of up to that long.
const TLS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const CHUNK_END: &[u8] = b"0\r\n\r\n";
/// How often an upgraded connection looks up from its socket to notice the
/// tunnel has gone.
const UPGRADE_POLL: Duration = Duration::from_secs(5);
const DEFAULT_TARGET: &str = "127.0.0.1:3000";
const FRAME_KEY_LABEL: &[u8] = b"tunnel-frame-encryption-key-v1";
const WRITE_QUEUE_MAX_BYTES: usize = 16 * 1024 * 1024;

fn build_crypto(token: &str) -> Result<Option<Arc<FrameCrypto>>, String> {
    if token.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Arc::new(FrameCrypto::from_token(token)?)))
    }
}

fn resolve_addr(flag: &str, addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .map_err(|e| format!("invalid {} '{}': {}", flag, addr, e))?
        .next()
        .ok_or_else(|| format!("{} '{}' resolved to no addresses", flag, addr))
}

fn resolve_target(target: &str) -> Result<std::net::SocketAddr, String> {
    resolve_addr("--target", target)
}

/// A local service a route key stands for. `raw` routes carry whole
/// connections (the gateway's `tunnel_h2` hosts) — h2c/gRPC bytes piped both
/// ways with no HTTP read in between.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Local {
    addr: std::net::SocketAddr,
    raw: bool,
}

const RAW_SCHEMES: [&str; 3] = ["h2c://", "grpc://", "tcp://"];

/// `KEY=HOST:PORT`, or `KEY=h2c://HOST:PORT` (also grpc://, tcp://) for a
/// route whose connections are relayed whole.
fn parse_route(spec: &str) -> Result<(String, Local), String> {
    let (key, target) = spec
        .split_once('=')
        .ok_or_else(|| format!("--route '{}': expected KEY=HOST:PORT", spec))?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!("--route '{}': empty key", spec));
    }
    let target = target.trim();
    let (raw, target) = match RAW_SCHEMES.iter().find_map(|p| target.strip_prefix(p)) {
        Some(rest) => (true, rest),
        None => (false, target.strip_prefix("http://").unwrap_or(target)),
    };
    Ok((key.to_string(), Local { addr: resolve_addr("--route", target)?, raw }))
}

/// Where a stream goes. The gateway names the route in the OPEN frame; no name
/// is the default target, as is every name when no routes were given — that is
/// what a single-target client has always done. A name this client was not
/// told about is refused rather than sent to some other service.
fn route_target(args: &Args, key: &[u8]) -> Result<Local, String> {
    let key = String::from_utf8_lossy(key);
    if key.is_empty() || args.routes.is_empty() {
        return Ok(Local { addr: args.target, raw: false });
    }
    args.routes
        .get(key.as_ref())
        .copied()
        .ok_or_else(|| format!("no local service for route '{}' — start the client with --route {}=HOST:PORT", key, key))
}

fn bad_gateway(reason: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        reason.len(),
        reason
    )
    .into_bytes()
}

fn enqueue_frame(
    queue: &(Mutex<Vec<Vec<u8>>>, std::sync::Condvar),
    frame: Vec<u8>,
    closed: &AtomicBool,
) {
    let mut q = lock_safe(&queue.0);
    let mut queued: usize = q.iter().map(|f| f.len()).sum();
    while queued + frame.len() > WRITE_QUEUE_MAX_BYTES
        && !q.is_empty()
        && !closed.load(Ordering::Relaxed)
    {
        let (g, _) = queue
            .1
            .wait_timeout(q, Duration::from_millis(50))
            .unwrap_or_else(|p| p.into_inner());
        q = g;
        queued = q.iter().map(|f| f.len()).sum();
    }
    q.push(frame);
    queue.1.notify_all();
}

fn encode_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.push(frame_type);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn decode_frame(data: &[u8]) -> Option<(u8, u32, usize, &[u8])> {
    if data.len() < FRAME_HEADER_LEN { return None; }
    let frame_type = data[0];
    let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if payload_len > 256 * 1024 * 1024 { return None; }
    let total = FRAME_HEADER_LEN + payload_len;
    if data.len() < total { return None; }
    Some((frame_type, stream_id, total, &data[FRAME_HEADER_LEN..total]))
}

fn lock_safe<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// TCP keepalive so a connection dropped by a NAT or a firewall is noticed
/// rather than sitting there looking healthy. socket2 knows what each platform
/// supports; only Linux lets the probe count be set.
fn enable_keepalive(stream: &TcpStream) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    #[cfg(target_os = "linux")]
    let ka = ka.with_retries(3);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

// --- Main ---

fn main() {
    let args = parse_args();
    let running = Arc::new(AtomicBool::new(true));
    let backend_healthy = Arc::new(AtomicBool::new(true));
    setup_signal_handler(&running);

    if args.insecure {
        eprintln!("[tunnel] WARNING: TLS certificate verification disabled (--insecure); the connection is vulnerable to man-in-the-middle attacks");
    }

    // Health check thread
    if let Some(ref health_path) = args.health_path {
        let target = args.target;
        let path = health_path.clone();
        let interval = args.health_interval;
        let restart_cmd = args.restart_cmd.clone();
        let healthy = Arc::clone(&backend_healthy);
        let run = Arc::clone(&running);
        let mut consecutive_failures = 0u32;

        std::thread::spawn(move || {
            loop {
                if !run.load(Ordering::Relaxed) { break; }
                std::thread::sleep(Duration::from_secs(interval));

                let ok = check_backend_health(target, &path);
                if ok {
                    if !healthy.load(Ordering::Relaxed) {
                        vlog!("[health] backend recovered");
                    }
                    healthy.store(true, Ordering::Relaxed);
                    consecutive_failures = 0;
                } else {
                    consecutive_failures += 1;
                    vlog!("[health] backend check failed ({}x)", consecutive_failures);
                    healthy.store(false, Ordering::Relaxed);

                    if consecutive_failures >= 3 {
                        if let Some(ref cmd) = restart_cmd {
                            vlog!("[health] restarting backend: {}", cmd);
                            let (shell, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
                            let _ = std::process::Command::new(shell).args([flag, cmd]).status();
                            consecutive_failures = 0;
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
            }
        });
    }

    let mut backoff = RECONNECT_BASE_MS;
    let started = std::time::Instant::now();

    while running.load(Ordering::Relaxed) {
        vlog!("[tunnel] connecting to {} as '{}'...", args.server, args.name);

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_tunnel(&args, &running)
        }));

        match outcome {
            Ok(Ok(())) => {
                vlog!("[tunnel] disconnected");
                backoff = RECONNECT_BASE_MS;
            }
            Ok(Err(e)) => {
                eprintln!("[tunnel] error: {}", e);
                backoff = next_backoff(backoff, &e, started.elapsed());
            }
            Err(_) => {
                eprintln!("[tunnel] panic recovered — reconnecting");
                backoff = (backoff * 2).min(RECONNECT_MAX_MS);
            }
        }

        if running.load(Ordering::Relaxed) {
            vlog!("[tunnel] reconnecting in {}ms...", backoff);
            std::thread::sleep(Duration::from_millis(backoff));
        }
    }
}

fn next_backoff(current: u64, error: &str, since_start: Duration) -> u64 {
    if error.starts_with("auth rejected") && since_start < FRESH_AUTH_WINDOW {
        return FRESH_AUTH_RETRY_MS;
    }
    (current * 2).min(RECONNECT_MAX_MS)
}

fn check_backend_health(target: std::net::SocketAddr, path: &str) -> bool {
    use std::io::{Read, Write};
    let mut stream = match TcpStream::connect_timeout(&target, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    if stream.write_all(req.as_bytes()).is_err() { return false; }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(n) if n > 12 => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            resp.contains("200") || resp.contains("204")
        }
        _ => false,
    }
}

fn run_tunnel(args: &Args, running: &AtomicBool) -> Result<(), String> {
    let tcp = TcpStream::connect_timeout(
        &resolve_addr("--server", &args.server)?,
        Duration::from_secs(10),
    ).map_err(|e| format!("connect: {}", e))?;
    tcp.set_nodelay(true).ok();
    enable_keepalive(&tcp);

    if args.tls {
        let tls_config = build_tls_config(args.insecure, &args.cert, &args.key);
        let server_name = extract_host(&args.server).to_string();
        let sni = rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|e| format!("invalid SNI: {}", e))?;
        let tls_conn = rustls::ClientConnection::new(tls_config, sni)
            .map_err(|e| format!("tls: {}", e))?;
        let mut tls_stream = rustls::StreamOwned::new(tls_conn, tcp);

        // TLS handshake + AUTH over blocking TLS
        do_auth(&mut tls_stream, args)?;

        let has_cert = args.cert.is_some();
        vlog!("[tunnel] connected (TLS{})! forwarding to {} ({} routes)",
            if has_cert { "+mTLS" } else { "" }, args.target, args.routes.len());

        // The handshake and AUTH are request/response, so they wait as long as
        // they need; the session that follows interleaves reads and writes on
        // this one thread, and only a bounded read lets a queued response go
        // out without waiting for the server to say something first.
        tls_stream.sock.set_read_timeout(Some(TLS_POLL_INTERVAL)).ok();
        run_tunnel_tls_loop(&mut tls_stream, args, running)
    } else {
        run_tunnel_on_stream(tcp, args, running)
    }
}

fn build_tls_config(insecure: bool, cert: &Option<String>, key: &Option<String>) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let builder = rustls::ClientConfig::builder();

    let with_verifier = if insecure {
        builder.dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(root_store)
    };

    let config = if let (Some(cert_path), Some(key_path)) = (cert, key) {
        let cert_file = std::fs::File::open(cert_path).expect("open client cert");
        let key_file = std::fs::File::open(key_path).expect("open client key");
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>().expect("parse client certs");
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
            .expect("parse client key").expect("no key found");
        with_verifier.with_client_auth_cert(certs, key).expect("client auth cert")
    } else {
        with_verifier.with_no_client_auth()
    };

    Arc::new(config)
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn extract_host(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match s.rsplit_once(':') {
        Some((host, _)) if !host.contains(':') => host,
        _ => s,
    }
}

fn do_auth<S: Read + Write>(stream: &mut S, args: &Args) -> Result<(), String> {
    let mut auth_payload = args.name.as_bytes().to_vec();
    auth_payload.push(0);
    auth_payload.extend_from_slice(args.token.as_bytes());
    stream.write_all(&encode_frame(FRAME_AUTH, 0, &auth_payload))
        .map_err(|e| format!("auth write: {}", e))?;

    let mut resp_buf = vec![0u8; 256];
    let n = stream.read(&mut resp_buf).map_err(|e| format!("auth read: {}", e))?;
    if n == 0 { return Err("connection closed during auth".into()); }

    match decode_frame(&resp_buf[..n]) {
        Some((FRAME_AUTH_OK, _, _, _)) => Ok(()),
        Some((FRAME_AUTH_ERR, _, _, payload)) => {
            Err(format!("auth rejected: {}", String::from_utf8_lossy(payload)))
        }
        _ => Err("unexpected auth response".into()),
    }
}

fn run_tunnel_tls_loop<S: Read + Write>(
    stream: &mut S,
    args: &Args,
    running: &AtomicBool,
) -> Result<(), String> {
    let closed = Arc::new(AtomicBool::new(false));
    let streams_map: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let write_queue: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)> = Arc::new((Mutex::new(Vec::new()), std::sync::Condvar::new()));
    let crypto = build_crypto(&args.token)?;

    let mut buffer = Vec::with_capacity(READ_BUF_SIZE);
    let mut read_buf = [0u8; READ_BUF_SIZE];
    let mut last_read = std::time::Instant::now();

    while !closed.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
        let frames: Vec<Vec<u8>> = {
            match write_queue.0.lock() {
                Ok(mut q) if !q.is_empty() => {
                    let taken = std::mem::take(&mut *q);
                    write_queue.1.notify_all();
                    taken
                }
                _ => Vec::new(),
            }
        };
        for frame in frames {
            if stream.write_all(&frame).is_err() { return Ok(()); }
        }

        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                last_read = std::time::Instant::now();
                buffer.extend_from_slice(&read_buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {
                if last_read.elapsed() > IDLE_READ_TIMEOUT {
                    vlog!("[client] tunnel idle > {:?}, treating as dead", IDLE_READ_TIMEOUT);
                    break;
                }
                continue;
            }
            Err(_) => break,
        }

        loop {
            match decode_frame(&buffer) {
                Some((ft, sid, consumed, payload)) => {
                    handle_frame(ft, sid, payload, args, &streams_map, &write_queue, &closed, &crypto);
                    buffer.drain(..consumed);
                }
                None => break,
            }
        }
    }
    Ok(())
}

fn run_tunnel_on_stream(mut stream: TcpStream, args: &Args, running: &AtomicBool) -> Result<(), String> {
    do_auth(&mut stream, args)?;
    vlog!("[tunnel] connected (TCP)! forwarding to {}", args.target);

    let closed = Arc::new(AtomicBool::new(false));
    let streams_map: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let write_queue: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)> =
        Arc::new((Mutex::new(Vec::new()), std::sync::Condvar::new()));
    let crypto = build_crypto(&args.token)?;

    let writer_stream = stream.try_clone().map_err(|e| format!("clone: {}", e))?;
    let wq_writer = Arc::clone(&write_queue);
    let closed_writer = Arc::clone(&closed);
    let writer = std::thread::spawn(move || {
        let closed_signal = Arc::clone(&closed_writer);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tunnel_writer_condvar(writer_stream, wq_writer, closed_writer);
        }));
        if r.is_err() {
            eprintln!("[client-writer] panic recovered");
        }
        closed_signal.store(true, Ordering::Release);
    });

    // Reader: main thread reads from tunnel stream
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let mut buffer = Vec::with_capacity(READ_BUF_SIZE);
    let mut read_buf = [0u8; READ_BUF_SIZE];
    let mut last_read = std::time::Instant::now();

    while !closed.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
        match stream.read(&mut read_buf) {
            Ok(0) => { vlog!("[client] tunnel EOF"); break; }
            Ok(n) => {
                last_read = std::time::Instant::now();
                buffer.extend_from_slice(&read_buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {
                if last_read.elapsed() > IDLE_READ_TIMEOUT {
                    vlog!("[client] tunnel idle > {:?}, treating as dead", IDLE_READ_TIMEOUT);
                    break;
                }
                continue;
            }
            Err(e) => { vlog!("[client] tunnel read error: {}", e); break; }
        }

        loop {
            match decode_frame(&buffer) {
                Some((frame_type, stream_id, consumed, payload)) => {
                    handle_frame(frame_type, stream_id, payload, args, &streams_map, &write_queue, &closed, &crypto);
                    buffer.drain(..consumed);
                }
                None => break,
            }
        }
    }

    closed.store(true, Ordering::Release);
    let _ = writer.join();
    Ok(())
}

fn handle_frame(
    frame_type: u8,
    stream_id: u32,
    payload: &[u8],
    args: &Args,
    streams_map: &Arc<Mutex<HashMap<u32, StreamState>>>,
    write_queue: &Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>,
    closed: &Arc<AtomicBool>,
    crypto: &Option<Arc<FrameCrypto>>,
) {
    // Decrypt DATA payload if encrypted
    let decrypted;
    let payload = if frame_type == FRAME_DATA {
        if let Some(ref c) = crypto {
            match c.decrypt(payload) {
                Some(d) => { decrypted = d; &decrypted }
                None => {
                    vlog!("[client] frame decrypt failed (len={})", payload.len());
                    return;
                }
            }
        } else { payload }
    } else { payload };
    match frame_type {
        FRAME_OPEN => {
            let state = match route_target(args, payload) {
                Ok(local) => match TcpStream::connect_timeout(&local.addr, Duration::from_secs(args.timeout)) {
                    Ok(s) => {
                        s.set_nodelay(true).ok();
                        let r = s.try_clone().ok();
                        StreamState { backend_writer: Some(s), backend_reader: r, failure: None, raw: local.raw }
                    }
                    Err(e) => StreamState {
                        backend_writer: None,
                        backend_reader: None,
                        failure: Some(format!("local service {} is not answering: {}", local.addr, e)),
                        raw: local.raw,
                    },
                },
                Err(reason) => {
                    vlog!("[client] {}", reason);
                    StreamState { backend_writer: None, backend_reader: None, failure: Some(reason), raw: false }
                }
            };
            let mut state = state;
            // A whole-connection route may be one whose server speaks first, so
            // its reader starts now rather than on the first byte from the client.
            let early = if state.raw { state.backend_reader.take() } else { None };
            let failed_raw = state.raw && state.backend_writer.is_none();
            lock_safe(streams_map).insert(stream_id, state);
            if let Some(reader_stream) = early {
                spawn_backend_reader(stream_id, reader_stream, args, write_queue, closed, crypto, true);
            }
            if failed_raw {
                queue_close(write_queue, stream_id);
            }
        }
        FRAME_DATA => {
            let start_reader = {
                let mut s = lock_safe(streams_map);
                if let Some(state) = s.get_mut(&stream_id) {
                    if let Some(ref mut bw) = state.backend_writer {
                        let _ = bw.write_all(payload);
                    }
                    // Take reader fd to spawn thread (only once)
                    state.backend_reader.take().map(|r| (r, state.raw))
                } else { None }
            };
            if let Some((reader_stream, raw)) = start_reader {
                spawn_backend_reader(stream_id, reader_stream, args, write_queue, closed, crypto, raw);
            } else {
                let s = lock_safe(streams_map);
                if let Some(state) = s.get(&stream_id) {
                    if state.backend_writer.is_none() && !state.raw {
                        let resp = bad_gateway(state.failure.as_deref().unwrap_or("local service unavailable"));
                        let resp = match crypto {
                            Some(c) => c.encrypt(&resp),
                            None => resp,
                        };
                        if let Ok(mut q) = write_queue.0.lock() {
                            q.push(encode_frame(FRAME_DATA, stream_id, &resp));
                            q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
                        }
                        write_queue.1.notify_one();
                    }
                }
            }
        }
        FRAME_CLOSE => {
            let mut s = lock_safe(streams_map);
            if let Some(state) = s.remove(&stream_id) {
                if let Some(bw) = state.backend_writer {
                    let _ = bw.shutdown(std::net::Shutdown::Both);
                }
            }
        }
        FRAME_PING => {
            if let Ok(mut q) = write_queue.0.lock() {
                q.push(encode_frame(FRAME_PONG, 0, &[]));
            }
            write_queue.1.notify_one();
        }
        _ => {}
    }
}

fn spawn_backend_reader(
    stream_id: u32,
    reader_stream: TcpStream,
    args: &Args,
    write_queue: &Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>,
    closed: &Arc<AtomicBool>,
    crypto: &Option<Arc<FrameCrypto>>,
    raw: bool,
) {
    let wq = Arc::clone(write_queue);
    let cl = Arc::clone(closed);
    let cr = crypto.clone();
    let read_timeout = Duration::from_secs(args.timeout);
    std::thread::spawn(move || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend_reader_simple(stream_id, reader_stream, wq, cl, cr, read_timeout, raw);
        }));
    });
}

fn queue_close(write_queue: &Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>, stream_id: u32) {
    if let Ok(mut q) = write_queue.0.lock() {
        q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
    }
    write_queue.1.notify_one();
}

fn tunnel_writer_condvar<W: Write>(mut writer: W, queue: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>, closed: Arc<AtomicBool>) {
    vlog!("[client-writer] started");
    loop {
        if closed.load(Ordering::Relaxed) { break; }
        let frames: Vec<Vec<u8>> = {
            let mut q = lock_safe(&queue.0);
            if q.is_empty() {
                let (q2, _) = queue.1
                    .wait_timeout(q, Duration::from_millis(1))
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                q = q2;
            }
            if q.is_empty() { continue; }
            let taken = std::mem::take(&mut *q);
            queue.1.notify_all();
            taken
        };
        let mut batch = Vec::with_capacity(frames.iter().map(|f| f.len()).sum());
        for f in frames { batch.extend_from_slice(&f); }
        if writer.write_all(&batch).is_err() {
            vlog!("[client-writer] write error");
            closed.store(true, Ordering::Release);
            return;
        }
    }
    vlog!("[client-writer] exited");
}

struct StreamState {
    backend_writer: Option<TcpStream>,
    backend_reader: Option<TcpStream>,
    failure: Option<String>,
    raw: bool,
}

/// The declared body length, if the response declares one.
fn content_length(lower_headers: &str) -> Option<usize> {
    lower_headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Statuses that carry no body whatever the headers say, so the response is
/// over the moment its headers are.
fn bodiless(lower_headers: &str) -> bool {
    let status = lower_headers.split_whitespace().nth(1).unwrap_or("");
    matches!(status, "204" | "304")
}

fn backend_reader_simple(
    stream_id: u32,
    mut backend: TcpStream,
    write_queue: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>,
    closed: Arc<AtomicBool>,
    crypto: Option<Arc<FrameCrypto>>,
    first_read_timeout: Duration,
    raw: bool,
) {
    let mut buf = [0u8; 32768];
    let mut got_data = false;
    let mut header_buf: Vec<u8> = Vec::with_capacity(MAX_HEADER_BYTES);
    let mut headers_parsed = raw;
    let mut subsequent_timeout = if raw { UPGRADE_POLL } else { Duration::from_millis(200) };
    // What the response itself says about where it ends. A backend that keeps
    // the connection open — which is every backend, by default — otherwise
    // leaves the reader waiting for a timeout it does not need, and that wait is
    // charged to the request.
    let mut body_target: Option<usize> = None;
    let mut is_chunked = false;
    let mut upgraded = raw;
    let mut total_read = 0usize;
    let mut header_len = 0usize;
    let mut tail = Vec::with_capacity(CHUNK_END.len());

    backend.set_read_timeout(Some(if raw { UPGRADE_POLL } else { first_read_timeout })).ok();

    loop {
        if closed.load(Ordering::Relaxed) { break; }
        match backend.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got_data = true;
                total_read += n;
                if !headers_parsed {
                    header_buf.extend_from_slice(&buf[..n]);
                    if let Some(end) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        headers_parsed = true;
                        header_len = end + 4;
                        let head = &header_buf[..end];
                        if let Ok(s) = std::str::from_utf8(head) {
                            let lower = s.to_ascii_lowercase();
                            let is_sse = lower.contains("content-type: text/event-stream")
                                || lower.contains("content-type:text/event-stream");
                            is_chunked = lower.contains("transfer-encoding: chunked")
                                || lower.contains("transfer-encoding:chunked");
                            // 101 means the response ended and a conversation
                            // began. Nothing about it says how long that
                            // conversation is, so silence must stop meaning the
                            // end of it — a websocket sits idle between
                            // messages, and treating the first quiet moment as
                            // the end closed the socket under the browser.
                            upgraded = lower.starts_with("http/1.1 101");
                            if upgraded {
                                subsequent_timeout = UPGRADE_POLL;
                            } else if is_sse {
                                subsequent_timeout = Duration::from_secs(600);
                            } else if is_chunked {
                                subsequent_timeout = Duration::from_secs(30);
                            } else {
                                body_target = content_length(&lower).or_else(|| bodiless(&lower).then_some(0));
                            }
                        }
                        header_buf.clear();
                        header_buf.shrink_to_fit();
                    } else if header_buf.len() > MAX_HEADER_BYTES {
                        headers_parsed = true;
                    }
                }
                let frame_payload = if let Some(ref c) = crypto {
                    c.encrypt(&buf[..n])
                } else {
                    buf[..n].to_vec()
                };
                enqueue_frame(&write_queue, encode_frame(FRAME_DATA, stream_id, &frame_payload), &closed);

                if headers_parsed {
                    if let Some(target) = body_target {
                        if total_read.saturating_sub(header_len) >= target { break; }
                    } else if is_chunked {
                        // The terminal chunk can straddle two reads, so the last
                        // few bytes are carried over.
                        let keep = CHUNK_END.len().saturating_sub(1);
                        tail.extend_from_slice(&buf[n.saturating_sub(CHUNK_END.len())..n]);
                        if tail.ends_with(CHUNK_END) { break; }
                        if tail.len() > keep { tail.drain(..tail.len() - keep); }
                    }
                }
                backend.set_read_timeout(Some(subsequent_timeout)).ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {
                // Silence ends an ordinary response. An upgraded connection is
                // not a response any more, so it only ends when a side closes
                // it or the tunnel goes away — the short poll is what keeps
                // that check responsive.
                if upgraded { continue; }
                if got_data { break; }
                continue;
            }
            Err(_) => break,
        }
    }

    if let Ok(mut q) = write_queue.0.lock() {
        q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
    }
    write_queue.1.notify_one();
}


// --- Shutdown ---

/// Ctrl+C (and SIGTERM where there is one) flips the run flag so the threads
/// wind down and the connection closes cleanly instead of being cut.
fn setup_signal_handler(running: &Arc<AtomicBool>) {
    let running = Arc::clone(running);
    let _ = ctrlc::set_handler(move || running.store(false, Ordering::Release));
}

// --- CLI ---

struct Args {
    server: String,
    name: String,
    token: String,
    target: std::net::SocketAddr,
    routes: HashMap<String, Local>,
    tls: bool,
    insecure: bool,
    cert: Option<String>,
    key: Option<String>,
    health_path: Option<String>,
    health_interval: u64,
    restart_cmd: Option<String>,
    timeout: u64,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut server = String::new();
    let mut name = String::new();
    let mut token = String::new();
    let mut target = String::new();
    let mut route_specs: Vec<String> = Vec::new();
    let mut tls = false;
    let mut insecure = false;
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut health_path: Option<String> = None;
    let mut health_interval: u64 = 30;
    let mut restart_cmd: Option<String> = None;
    let mut timeout: u64 = 30;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => { i += 1; if i < args.len() { server = args[i].clone(); } }
            "--name" | "-n" => { i += 1; if i < args.len() { name = args[i].clone(); } }
            "--token" | "-t" => { i += 1; if i < args.len() { token = args[i].clone(); } }
            "--target" | "-T" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--route" | "-r" => { i += 1; if i < args.len() { route_specs.push(args[i].clone()); } }
            "--cert" => { i += 1; if i < args.len() { cert = Some(args[i].clone()); tls = true; } }
            "--key" => { i += 1; if i < args.len() { key = Some(args[i].clone()); } }
            "--tls" => { tls = true; }
            "--insecure" | "-k" => { insecure = true; tls = true; }
            "--health" => { i += 1; if i < args.len() { health_path = Some(args[i].clone()); } }
            "--health-interval" => { i += 1; if i < args.len() { health_interval = args[i].parse().unwrap_or(30); } }
            "--restart-cmd" => { i += 1; if i < args.len() { restart_cmd = Some(args[i].clone()); } }
            "--timeout" => { i += 1; if i < args.len() { timeout = args[i].parse().unwrap_or(30); } }
            "--help" | "-h" => {
                eprintln!("Usage: gateway-tunnel [OPTIONS]");
                eprintln!("  -s, --server HOST:PORT   Tunnel server address");
                eprintln!("  -n, --name   NAME        Tunnel name");
                eprintln!("  -t, --token  TOKEN       Auth token");
                eprintln!("  -T, --target HOST:PORT   Local service (default: 127.0.0.1:3000)");
                eprintln!("  -r, --route KEY=HOST:PORT  Local service for the gateway's tunnel_route KEY (repeatable);");
                eprintln!("                           KEY=h2c://HOST:PORT relays whole connections (gRPC, tunnel_h2 hosts)");
                eprintln!("  --tls                    Enable TLS");
                eprintln!("  --cert FILE              Client certificate (enables mTLS)");
                eprintln!("  --key FILE               Client private key");
                eprintln!("  --insecure, -k           Skip server cert verification");
                eprintln!("  --health PATH            Health check path (e.g. /health)");
                eprintln!("  --health-interval SECS   Health check interval (default: 30)");
                eprintln!("  --restart-cmd CMD        Restart backend on health failure");
                eprintln!("  --timeout SECS           Request timeout (default: 30)");
                std::process::exit(0);
            }
            _ => { if server.is_empty() { server = args[i].clone(); } }
        }
        i += 1;
    }

    if server.is_empty() { server = std::env::var("TUNNEL_SERVER").unwrap_or_default(); }
    if name.is_empty() { name = std::env::var("TUNNEL_NAME").unwrap_or_default(); }
    if token.is_empty() { token = std::env::var("TUNNEL_TOKEN").unwrap_or_default(); }
    if target.is_empty() { target = std::env::var("TUNNEL_TARGET").unwrap_or_else(|_| DEFAULT_TARGET.into()); }
    if route_specs.is_empty() {
        if let Ok(v) = std::env::var("TUNNEL_ROUTES") {
            route_specs = v.split(',').map(str::trim).filter(|r| !r.is_empty()).map(String::from).collect();
        }
    }
    if !tls && std::env::var("TUNNEL_TLS").map(|v| v == "true" || v == "1").unwrap_or(false) { tls = true; }
    if cert.is_none() { cert = std::env::var("TUNNEL_CERT").ok(); if cert.is_some() { tls = true; } }
    if key.is_none() { key = std::env::var("TUNNEL_KEY").ok(); }
    if health_path.is_none() { health_path = std::env::var("TUNNEL_HEALTH").ok(); }
    if restart_cmd.is_none() { restart_cmd = std::env::var("TUNNEL_RESTART_CMD").ok(); }

    if server.is_empty() || name.is_empty() {
        eprintln!("Error: --server and --name required");
        std::process::exit(1);
    }

    let target = match resolve_target(&target) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let routes = match route_specs.iter().map(|r| parse_route(r)).collect::<Result<HashMap<_, _>, _>>() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    Args { server, name, token, target, routes, tls, insecure, cert, key, health_path, health_interval, restart_cmd, timeout }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = encode_frame(FRAME_DATA, 42, b"hello");
        let (ft, sid, total, payload) = decode_frame(&f).unwrap();
        assert_eq!(ft, FRAME_DATA);
        assert_eq!(sid, 42);
        assert_eq!(total, f.len());
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn frame_empty() {
        let f = encode_frame(FRAME_PING, 0, &[]);
        let (ft, _, _, payload) = decode_frame(&f).unwrap();
        assert_eq!(ft, FRAME_PING);
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn frame_incomplete() {
        assert!(decode_frame(&[0x01]).is_none());
    }

    #[test]
    fn auth_frame() {
        let mut payload = b"my-app".to_vec();
        payload.push(0);
        payload.extend_from_slice(b"secret");
        let f = encode_frame(FRAME_AUTH, 0, &payload);
        let (ft, _, _, p) = decode_frame(&f).unwrap();
        assert_eq!(ft, FRAME_AUTH);
        let pos = p.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&p[..pos], b"my-app");
        assert_eq!(&p[pos + 1..], b"secret");
    }

    #[test]
    fn target_hostname_resolved_not_rewritten() {
        assert!(resolve_target("127.0.0.1:3000").is_ok());
        assert!(resolve_target("localhost:3000").is_ok());
    }

    #[test]
    fn target_invalid_rejected() {
        assert!(resolve_target("localhost").is_err());
        assert!(resolve_target("not a valid target").is_err());
    }

    #[test]
    fn extract_host_handles_ipv6() {
        assert_eq!(extract_host("[::1]:8443"), "::1");
        assert_eq!(extract_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(extract_host("example.com:443"), "example.com");
        assert_eq!(extract_host("example.com"), "example.com");
        assert_eq!(extract_host("::1"), "::1");
    }

    fn args_with(routes: &[&str]) -> Args {
        Args {
            server: "x:1".into(),
            name: "n".into(),
            token: String::new(),
            target: resolve_target("127.0.0.1:3000").unwrap(),
            routes: routes.iter().map(|r| parse_route(r).unwrap()).collect(),
            tls: false,
            insecure: false,
            cert: None,
            key: None,
            health_path: None,
            health_interval: 30,
            restart_cmd: None,
            timeout: 1,
        }
    }

    #[test]
    fn a_route_spec_names_a_key_and_a_target() {
        let (k, t) = parse_route("api=127.0.0.1:8030").unwrap();
        assert_eq!((k.as_str(), t.addr.port(), t.raw), ("api", 8030, false));
        for spec in ["g=h2c://127.0.0.1:6334", "g=grpc://127.0.0.1:6334", "g=tcp://127.0.0.1:6334"] {
            let (_, t) = parse_route(spec).unwrap();
            assert_eq!((t.addr.port(), t.raw), (6334, true), "{spec}");
        }
        assert!(!parse_route("w=http://127.0.0.1:80").unwrap().1.raw);
        assert!(parse_route("api").is_err());
        assert!(parse_route("=127.0.0.1:1").is_err());
        assert!(parse_route("api=nowhere").is_err());
    }

    #[test]
    fn each_route_key_reaches_its_own_port() {
        let a = args_with(&["web=127.0.0.1:3000", "api=127.0.0.1:8030"]);
        assert_eq!(route_target(&a, b"api").unwrap().addr.port(), 8030);
        assert_eq!(route_target(&a, b"web").unwrap().addr.port(), 3000);
    }

    #[test]
    fn no_key_is_the_default_target() {
        let a = args_with(&["api=127.0.0.1:8030"]);
        assert_eq!(route_target(&a, b"").unwrap().addr.port(), 3000);
    }

    #[test]
    fn a_single_target_client_serves_every_key() {
        let a = args_with(&[]);
        assert_eq!(route_target(&a, b"api").unwrap().addr.port(), 3000);
    }

    #[test]
    fn an_unknown_key_is_refused_not_misrouted() {
        let a = args_with(&["api=127.0.0.1:8030"]);
        let err = route_target(&a, b"admin").unwrap_err();
        assert!(err.contains("--route admin="), "{err}");
    }

    #[test]
    fn a_refusal_is_a_complete_response() {
        let r = String::from_utf8(bad_gateway("why")).unwrap();
        assert!(r.starts_with("HTTP/1.1 502"));
        assert!(r.contains("content-length: 3\r\n"));
        assert!(r.ends_with("\r\n\r\nwhy"));
    }

    fn queued_frames(q: &Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>) -> Vec<(u8, Vec<u8>)> {
        lock_safe(&q.0).iter().filter_map(|f| decode_frame(f).map(|(t, _, _, p)| (t, p.to_vec()))).collect()
    }

    #[test]
    fn a_raw_route_pipes_bytes_both_ways_without_reading_http() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.write_all(b"PRI-greeting").unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            c.write_all(&buf[..n]).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let args = args_with(&[&format!("g=h2c://127.0.0.1:{port}")]);
        let streams: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
        let q: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)> = Arc::new((Mutex::new(Vec::new()), std::sync::Condvar::new()));
        let closed = Arc::new(AtomicBool::new(false));
        handle_frame(FRAME_OPEN, 1, b"g", &args, &streams, &q, &closed, &None);
        std::thread::sleep(Duration::from_millis(150));
        assert!(queued_frames(&q).iter().any(|(t, p)| *t == FRAME_DATA && p == b"PRI-greeting"), "server-first bytes not relayed");
        handle_frame(FRAME_DATA, 1, b"\x00\x01binary-not-http", &args, &streams, &q, &closed, &None);
        std::thread::sleep(Duration::from_millis(150));
        let frames = queued_frames(&q);
        assert!(frames.iter().any(|(t, p)| *t == FRAME_DATA && p == b"\x00\x01binary-not-http"), "{frames:?}");
        assert!(!frames.iter().any(|(t, p)| *t == FRAME_DATA && p.starts_with(b"HTTP/1.1 502")));
        closed.store(true, Ordering::Release);
    }

    #[test]
    fn an_unreachable_raw_route_closes_instead_of_answering_http() {
        let args = args_with(&["g=h2c://127.0.0.1:1"]);
        let streams: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
        let q: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)> = Arc::new((Mutex::new(Vec::new()), std::sync::Condvar::new()));
        let closed = Arc::new(AtomicBool::new(false));
        handle_frame(FRAME_OPEN, 7, b"g", &args, &streams, &q, &closed, &None);
        let frames = queued_frames(&q);
        assert!(frames.iter().any(|(t, _)| *t == FRAME_CLOSE));
        assert!(!frames.iter().any(|(t, _)| *t == FRAME_DATA));
    }

    #[test]
    fn an_early_auth_reject_is_retried_at_once_later_ones_back_off() {
        let early = next_backoff(4000, "auth rejected: unauthorized", Duration::from_secs(3));
        assert_eq!(early, FRESH_AUTH_RETRY_MS);
        assert_eq!(next_backoff(4000, "auth rejected: unauthorized", Duration::from_secs(60)), 8000);
        assert_eq!(next_backoff(4000, "connect: refused", Duration::from_secs(1)), 8000);
        assert_eq!(next_backoff(RECONNECT_MAX_MS, "connect: refused", Duration::from_secs(1)), RECONNECT_MAX_MS);
    }
}
