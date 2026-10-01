use crate::error::DnsError;
use crate::message::{build_query, parse_response, Answer, RecordType};
use std::net::UdpSocket;
use std::time::Duration;

fn generate_id() -> u16 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        & 0xFFFF) as u16
}

pub fn resolve(
    server: &str,
    domain: &str,
    rtype: RecordType,
    timeout: Duration,
) -> Result<Vec<Answer>, DnsError> {
    let id = generate_id();
    let query = build_query(id, domain, rtype)?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send_to(&query, (server, 53))?;

    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf)?;
    parse_response(&buf[..len], id)
}

/// Повторює запит, якщо відповідь не надійшла вчасно.
pub fn resolve_with_retries(
    server: &str,
    domain: &str,
    rtype: RecordType,
    timeout: Duration,
    retries: u32,
) -> Result<Vec<Answer>, DnsError> {
    let attempts = retries.max(1);
    let mut last = DnsError::Timeout;
    for _ in 0..attempts {
        match resolve(server, domain, rtype, timeout) {
            Err(DnsError::Timeout) => last = DnsError::Timeout,
            other => return other, 
        }
    }
    Err(last)
}