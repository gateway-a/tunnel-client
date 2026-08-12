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
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(30);
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

fn enable_keepalive(stream: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        #[cfg(target_os = "linux")]
        let keepidle_opt = libc::TCP_KEEPIDLE;
        #[cfg(target_os = "macos")]
        let keepidle_opt = libc::TCP_KEEPALIVE;
        let idle: libc::c_int = 30;
        libc::setsockopt(
            fd, libc::IPPROTO_TCP, keepidle_opt,
            &idle as *const _ as *const libc::c_void,
            std::mem::size_of_val(&idle) as libc::socklen_t,
        );
        let intvl: libc::c_int = 10;
        libc::setsockopt(
            fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL,
            &intvl as *const _ as *const libc::c_void,
            std::mem::size_of_val(&intvl) as libc::socklen_t,
        );
        let cnt: libc::c_int = 3;
        libc::setsockopt(
            fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT,
            &cnt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&cnt) as libc::socklen_t,
        );
    }
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
                            let _ = std::process::Command::new("sh")
                                .args(["-c", cmd])
                                .status();
                            consecutive_failures = 0;
                            std::thread::sleep(Duration::from_secs(5));
                        }
                    }
                }
            }
        });
    }

    let mut backoff = RECONNECT_BASE_MS;

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
                backoff = (backoff * 2).min(RECONNECT_MAX_MS);
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
        vlog!("[tunnel] connected (TLS{})! forwarding to {}",
            if has_cert { "+mTLS" } else { "" }, args.target);

        // For TLS we use single-thread read+write with timeout
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
            let (bw, br) = match TcpStream::connect_timeout(
                &args.target,
                Duration::from_secs(args.timeout),
            ) {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    let r = s.try_clone().ok();
                    (Some(s), r)
                }
                Err(_) => (None, None),
            };
            let mut s = lock_safe(streams_map);
            s.insert(stream_id, StreamState { backend_writer: bw, backend_reader: br });
        }
        FRAME_DATA => {
            let start_reader = {
                let mut s = lock_safe(streams_map);
                if let Some(state) = s.get_mut(&stream_id) {
                    if let Some(ref mut bw) = state.backend_writer {
                        let _ = bw.write_all(payload);
                    }
                    // Take reader fd to spawn thread (only once)
                    state.backend_reader.take()
                } else { None }
            };
            if let Some(reader_stream) = start_reader {
                let wq = Arc::clone(write_queue);
                let cl = Arc::clone(closed);
                let cr = crypto.clone();
                let read_timeout = Duration::from_secs(args.timeout);
                std::thread::spawn(move || {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        backend_reader_simple(stream_id, reader_stream, wq, cl, cr, read_timeout);
                    }));
                });
            } else {
                let s = lock_safe(streams_map);
                if let Some(state) = s.get(&stream_id) {
                    if state.backend_writer.is_none() {
                        let resp = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n";
                        if let Ok(mut q) = write_queue.0.lock() {
                            q.push(encode_frame(FRAME_DATA, stream_id, resp));
                            q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
                        }
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
}

fn backend_reader_simple(
    stream_id: u32,
    mut backend: TcpStream,
    write_queue: Arc<(Mutex<Vec<Vec<u8>>>, std::sync::Condvar)>,
    closed: Arc<AtomicBool>,
    crypto: Option<Arc<FrameCrypto>>,
    first_read_timeout: Duration,
) {
    let mut buf = [0u8; 32768];
    let mut got_data = false;
    let mut header_buf: Vec<u8> = Vec::with_capacity(2048);
    let mut headers_parsed = false;
    let mut subsequent_timeout = Duration::from_millis(200);

    backend.set_read_timeout(Some(first_read_timeout)).ok();

    loop {
        if closed.load(Ordering::Relaxed) { break; }
        match backend.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got_data = true;
                if !headers_parsed {
                    header_buf.extend_from_slice(&buf[..n.min(2048)]);
                    if let Some(end) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        headers_parsed = true;
                        let head = &header_buf[..end];
                        if let Ok(s) = std::str::from_utf8(head) {
                            let lower = s.to_ascii_lowercase();
                            let is_sse = lower.contains("content-type: text/event-stream")
                                || lower.contains("content-type:text/event-stream");
                            let is_chunked = lower.contains("transfer-encoding: chunked")
                                || lower.contains("transfer-encoding:chunked");
                            if is_sse {
                                subsequent_timeout = Duration::from_secs(600);
                            } else if is_chunked {
                                subsequent_timeout = Duration::from_secs(30);
                            }
                        }
                        header_buf.clear();
                        header_buf.shrink_to_fit();
                    } else if header_buf.len() > 2048 {
                        headers_parsed = true;
                    }
                }
                let frame_payload = if let Some(ref c) = crypto {
                    c.encrypt(&buf[..n])
                } else {
                    buf[..n].to_vec()
                };
                enqueue_frame(&write_queue, encode_frame(FRAME_DATA, stream_id, &frame_payload), &closed);
                backend.set_read_timeout(Some(subsequent_timeout)).ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {
                // If we already got data and timeout → response complete
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


// --- Signal handling ---

fn setup_signal_handler(running: &Arc<AtomicBool>) {
    RUNNING_PTR.store(Arc::as_ptr(running) as *mut _, Ordering::Release);
    unsafe {
        libc::signal(libc::SIGINT, sig_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, sig_handler as libc::sighandler_t);
    }
}

static RUNNING_PTR: std::sync::atomic::AtomicPtr<AtomicBool> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

extern "C" fn sig_handler(_: libc::c_int) {
    let ptr = RUNNING_PTR.load(Ordering::Acquire);
    if !ptr.is_null() {
        unsafe { &*ptr }.store(false, Ordering::Release);
    }
}

// --- CLI ---

struct Args {
    server: String,
    name: String,
    token: String,
    target: std::net::SocketAddr,
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

    Args { server, name, token, target, tls, insecure, cert, key, health_path, health_interval, restart_cmd, timeout }
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
}
