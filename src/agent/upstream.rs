use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn forward_to_upstream(addr: &str, request_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request_data).await?;

    let mut response = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];

    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| anyhow::anyhow!("upstream read timeout"))??;

        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);

        if response_complete(&response) {
            break;
        }
    }

    Ok(response)
}

fn response_complete(data: &[u8]) -> bool {
    let header_end = match find_header_end(data) {
        Some(pos) => pos,
        None => return false,
    };

    let header_part = &data[..header_end];

    if let Some(cl) = parse_content_length(header_part) {
        let body_start = header_end + 4;
        return data.len() >= body_start + cl;
    }

    if has_chunked_encoding(header_part) {
        return data.ends_with(b"0\r\n\r\n");
    }

    true
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n") {
        if let Some(val) = line.strip_prefix("Content-Length: ")
            .or_else(|| line.strip_prefix("content-length: "))
        {
            return val.trim().parse().ok();
        }
    }
    None
}

fn has_chunked_encoding(headers: &[u8]) -> bool {
    let s = match std::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.to_ascii_lowercase().contains("transfer-encoding: chunked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_complete_with_content_length() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(response_complete(resp));
    }

    #[test]
    fn response_incomplete_with_content_length() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        assert!(!response_complete(resp));
    }

    #[test]
    fn response_complete_chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(response_complete(resp));
    }

    #[test]
    fn response_incomplete_no_headers() {
        let resp = b"HTTP/1.1 200 OK\r\nContent";
        assert!(!response_complete(resp));
    }

    #[test]
    fn parse_content_length_cases() {
        assert_eq!(parse_content_length(b"Content-Length: 42"), Some(42));
        assert_eq!(parse_content_length(b"content-length: 0"), Some(0));
        assert_eq!(parse_content_length(b"X-Custom: foo"), None);
    }
}
