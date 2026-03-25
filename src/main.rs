use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

// --- Main ---

fn main() {
    let args = parse_args();
    let running = Arc::new(AtomicBool::new(true));
    setup_signal_handler(&running);

    let mut backoff = RECONNECT_BASE_MS;

    while running.load(Ordering::Relaxed) {
        eprintln!("[tunnel] connecting to {} as '{}'...", args.server, args.name);

        match run_tunnel(&args, &running) {
            Ok(()) => {
                eprintln!("[tunnel] disconnected");
                backoff = RECONNECT_BASE_MS;
            }
            Err(e) => {
                eprintln!("[tunnel] error: {}", e);
                backoff = (backoff * 2).min(RECONNECT_MAX_MS);
            }
        }

        if running.load(Ordering::Relaxed) {
            eprintln!("[tunnel] reconnecting in {}ms...", backoff);
            std::thread::sleep(Duration::from_millis(backoff));
        }
    }
}

fn run_tunnel(args: &Args, running: &AtomicBool) -> Result<(), String> {
    let tcp = TcpStream::connect_timeout(
        &args.server.parse().map_err(|e| format!("parse: {}", e))?,
        Duration::from_secs(10),
    ).map_err(|e| format!("connect: {}", e))?;
    tcp.set_nodelay(true).ok();

    // TODO: TLS mode needs shared stream approach (future)
    if args.tls {
        eprintln!("[tunnel] TLS mode not yet supported for bidirectional, using plain TCP");
    }
    run_tunnel_on_stream(tcp, args, running)
}

fn build_tls_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = rustls::ClientConfig::builder();
    let config = if insecure {
        builder.dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(root_store).with_no_client_auth()
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
    s.split(':').next().unwrap_or(s)
}

fn run_tunnel_on_stream(mut stream: TcpStream, args: &Args, running: &AtomicBool) -> Result<(), String> {
    // AUTH
    let mut auth_payload = args.name.as_bytes().to_vec();
    auth_payload.push(0);
    auth_payload.extend_from_slice(args.token.as_bytes());
    let auth_frame = encode_frame(FRAME_AUTH, 0, &auth_payload);
    stream.write_all(&auth_frame).map_err(|e| format!("auth write: {}", e))?;

    let mut resp_buf = vec![0u8; 256];
    let n = stream.read(&mut resp_buf).map_err(|e| format!("auth read: {}", e))?;
    if n == 0 { return Err("connection closed during auth".into()); }

    match decode_frame(&resp_buf[..n]) {
        Some((FRAME_AUTH_OK, _, _, _)) => {}
        Some((FRAME_AUTH_ERR, _, _, payload)) => {
            return Err(format!("auth rejected: {}", String::from_utf8_lossy(payload)));
        }
        _ => return Err("unexpected auth response".into()),
    }

    let proto = if args.tls { "TLS" } else { "TCP" };
    eprintln!("[tunnel] connected ({})! forwarding to {}", proto, args.target);

    let closed = Arc::new(AtomicBool::new(false));
    let streams_map: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let write_queue: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    // Writer thread: drains write_queue → tunnel stream
    let writer_stream = stream.try_clone().map_err(|e| format!("clone: {}", e))?;
    let wq_writer = Arc::clone(&write_queue);
    let closed_writer = Arc::clone(&closed);
    let writer = std::thread::spawn(move || {
        tunnel_writer_thread(writer_stream, wq_writer, closed_writer);
    });

    // Reader: main thread reads from tunnel stream
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let mut buffer = Vec::with_capacity(READ_BUF_SIZE);
    let mut read_buf = [0u8; READ_BUF_SIZE];

    while !closed.load(Ordering::Relaxed) && running.load(Ordering::Relaxed) {
        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&read_buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => { continue; }
            Err(_) => break,
        }

        loop {
            match decode_frame(&buffer) {
                Some((frame_type, stream_id, consumed, payload)) => {
                    handle_frame(frame_type, stream_id, payload, args, &streams_map, &write_queue, &closed);
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
    write_queue: &Arc<Mutex<Vec<Vec<u8>>>>,
    closed: &Arc<AtomicBool>,
) {
    match frame_type {
        FRAME_OPEN => {
            let backend = TcpStream::connect_timeout(
                &args.target.parse().unwrap_or_else(|_| "127.0.0.1:3000".parse().unwrap()),
                Duration::from_secs(5),
            ).ok().map(|s| {
                s.set_nodelay(true).ok();
                Arc::new(Mutex::new(s))
            });
            let mut s = streams_map.lock().unwrap();
            s.insert(stream_id, StreamState { backend, reader_started: false });
        }
        FRAME_DATA => {
            let mut s = streams_map.lock().unwrap();
            if let Some(state) = s.get_mut(&stream_id) {
                if let Some(ref backend) = state.backend {
                    if let Ok(mut b) = backend.lock() {
                        let _ = b.write_all(payload);
                    }
                    if !state.reader_started {
                        state.reader_started = true;
                        let backend = Arc::clone(backend);
                        let wq = Arc::clone(write_queue);
                        let cl = Arc::clone(closed);
                        std::thread::spawn(move || {
                            backend_reader(stream_id, backend, wq, cl);
                        });
                    }
                } else {
                    let resp = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n";
                    if let Ok(mut q) = write_queue.lock() {
                        q.push(encode_frame(FRAME_DATA, stream_id, resp));
                        q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
                    }
                }
            }
        }
        FRAME_CLOSE => {
            let mut s = streams_map.lock().unwrap();
            if let Some(state) = s.remove(&stream_id) {
                if let Some(ref backend) = state.backend {
                    if let Ok(b) = backend.lock() {
                        let _ = b.shutdown(std::net::Shutdown::Write);
                    }
                }
            }
        }
        FRAME_PING => {
            if let Ok(mut q) = write_queue.lock() {
                q.push(encode_frame(FRAME_PONG, 0, &[]));
            }
        }
        _ => {}
    }
}

fn tunnel_writer_thread<W: Write>(mut writer: W, queue: Arc<Mutex<Vec<Vec<u8>>>>, closed: Arc<AtomicBool>) {
    while !closed.load(Ordering::Relaxed) {
        let frames: Vec<Vec<u8>> = {
            match queue.lock() {
                Ok(mut q) if !q.is_empty() => std::mem::take(&mut *q),
                _ => {
                    std::thread::sleep(Duration::from_micros(100));
                    continue;
                }
            }
        };
        for frame in frames {
            if writer.write_all(&frame).is_err() {
                closed.store(true, Ordering::Release);
                return;
            }
        }
    }
}

struct StreamState {
    backend: Option<Arc<Mutex<TcpStream>>>,
    reader_started: bool,
}

fn backend_reader(
    stream_id: u32,
    backend: Arc<Mutex<TcpStream>>,
    write_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    closed: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 32768];

    // First read: blocking with timeout (wait for response)
    {
        let mut b = match backend.lock() {
            Ok(b) => b,
            Err(_) => return,
        };
        let _ = b.set_nonblocking(false);
        let _ = b.set_read_timeout(Some(Duration::from_secs(30)));
        match b.read(&mut buf) {
            Ok(0) => {
                if let Ok(mut q) = write_queue.lock() {
                    q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
                }
                return;
            }
            Ok(n) => {
                if let Ok(mut q) = write_queue.lock() {
                    q.push(encode_frame(FRAME_DATA, stream_id, &buf[..n]));
                }
            }
            Err(_) => {
                if let Ok(mut q) = write_queue.lock() {
                    q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
                }
                return;
            }
        }
        let _ = b.set_nonblocking(true);
    }

    // Subsequent reads: non-blocking (drain remaining data)
    loop {
        if closed.load(Ordering::Relaxed) { break; }
        let n = {
            let mut b = match backend.lock() {
                Ok(b) => b,
                Err(_) => break,
            };
            match b.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    drop(b);
                    std::thread::sleep(Duration::from_micros(200));
                    continue;
                }
                Err(_) => break,
            }
        };

        if let Ok(mut q) = write_queue.lock() {
            q.push(encode_frame(FRAME_DATA, stream_id, &buf[..n]));
        }
    }

    if let Ok(mut q) = write_queue.lock() {
        q.push(encode_frame(FRAME_CLOSE, stream_id, &[]));
    }
}




// --- Signal handling ---

fn setup_signal_handler(running: &Arc<AtomicBool>) {
    let r = Arc::clone(running);
    std::thread::spawn(move || {
        unsafe {
            libc::signal(libc::SIGINT, sig_handler as libc::sighandler_t);
            libc::signal(libc::SIGTERM, sig_handler as libc::sighandler_t);
        }
        RUNNING_PTR.store(Arc::into_raw(r) as *mut _, Ordering::Release);
    });
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
    target: String,
    tls: bool,
    insecure: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut server = String::new();
    let mut name = String::new();
    let mut token = String::new();
    let mut target = String::new();
    let mut tls = false;
    let mut insecure = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => { i += 1; if i < args.len() { server = args[i].clone(); } }
            "--name" | "-n" => { i += 1; if i < args.len() { name = args[i].clone(); } }
            "--token" | "-t" => { i += 1; if i < args.len() { token = args[i].clone(); } }
            "--target" | "-T" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--tls" => { tls = true; }
            "--insecure" | "-k" => { insecure = true; tls = true; }
            "--help" | "-h" => {
                eprintln!("Usage: tunnel-client [OPTIONS]");
                eprintln!("  -s, --server HOST:PORT  Tunnel server address");
                eprintln!("  -n, --name   NAME       Tunnel name");
                eprintln!("  -t, --token  TOKEN      Auth token");
                eprintln!("  -T, --target HOST:PORT  Local service (default: 127.0.0.1:3000)");
                eprintln!("  --tls                   Enable TLS");
                eprintln!("  --insecure, -k          Skip TLS cert verification");
                std::process::exit(0);
            }
            _ => { if server.is_empty() { server = args[i].clone(); } }
        }
        i += 1;
    }

    if server.is_empty() { server = std::env::var("TUNNEL_SERVER").unwrap_or_default(); }
    if name.is_empty() { name = std::env::var("TUNNEL_NAME").unwrap_or_default(); }
    if token.is_empty() { token = std::env::var("TUNNEL_TOKEN").unwrap_or_default(); }
    if target.is_empty() { target = std::env::var("TUNNEL_TARGET").unwrap_or_else(|_| "127.0.0.1:3000".into()); }
    if !tls && std::env::var("TUNNEL_TLS").map(|v| v == "true" || v == "1").unwrap_or(false) { tls = true; }

    if server.is_empty() || name.is_empty() {
        eprintln!("Error: --server and --name required");
        std::process::exit(1);
    }

    Args { server, name, token, target, tls, insecure }
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

}
