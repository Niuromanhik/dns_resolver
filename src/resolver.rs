use crate::error::DnsError;
use crate::message::{build_query, parse_response, Answer, RecordType};
use std::net::UdpSocket;
use std::time::Duration;

pub fn resolve(
    server: &str,
    domain: &str,
    rtype: RecordType,
    timeout: Duration,
) -> Result<Vec<Answer>, DnsError> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        & 0xFFFF) as u16;

    let query = build_query(id, domain, rtype)?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.send_to(&query, (server, 53))?;

    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf)?;
    parse_response(&buf[..len], id)
}