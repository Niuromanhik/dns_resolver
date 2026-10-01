use crate::error::DnsError;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
        }
    }
}

#[derive(Debug)]
pub struct Answer {
    pub address: String,
    pub record_type: RecordType,
    pub ttl: u32,
}

/// Будує DNS-запит.
pub fn build_query(id: u16, domain: &str, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::with_capacity(512);

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); 
    buf.extend_from_slice(&1u16.to_be_bytes()); 
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); 

    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return Err(DnsError::InvalidDomain(domain.to_string()));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(DnsError::InvalidDomain(domain.to_string()));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);

    buf.extend_from_slice(&rtype.code().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); 
    Ok(buf)
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, DnsError> {
    buf.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(DnsError::MalformedResponse("неочікуваний кінець пакета"))
}

fn read_u32(buf: &[u8], pos: usize) -> Result<u32, DnsError> {
    buf.get(pos..pos + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(DnsError::MalformedResponse("неочікуваний кінець пакета"))
}

/// Пропускає імʼя (з урахуванням стиснення) і повертає позицію після нього.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *buf
            .get(pos)
            .ok_or(DnsError::MalformedResponse("неочікуваний кінець пакета"))?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Розбирає відповідь сервера.
pub fn parse_response(buf: &[u8], expected_id: u16) -> Result<Vec<Answer>, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::MalformedResponse("пакет коротший за заголовок"));
    }
    if read_u16(buf, 0)? != expected_id {
        return Err(DnsError::IdMismatch);
    }
    let flags = read_u16(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::MalformedResponse("це не відповідь"));
    }
    let rcode = (flags & 0x000F) as u8;
    if rcode != 0 {
        return Err(DnsError::ServerError(rcode));
    }

    let qdcount = read_u16(buf, 4)?;
    let ancount = read_u16(buf, 6)?;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let rtype = read_u16(buf, pos)?;
        let ttl = read_u32(buf, pos + 4)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;

        let data = buf
            .get(pos..pos + rdlen)
            .ok_or(DnsError::MalformedResponse("RDATA виходить за межі пакета"))?;
        pos += rdlen;

        match (rtype, rdlen) {
            (1, 4) => answers.push(Answer {
                address: Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
                record_type: RecordType::A,
                ttl,
            }),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                answers.push(Answer {
                    address: Ipv6Addr::from(octets).to_string(),
                    record_type: RecordType::AAAA,
                    ttl,
                });
            }
            _ => {} 
        }
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Будує відповідь на основі запиту: ставить прапорці відповіді, rcode і додає answer-секцію.
    fn response_with(id: u16, rcode: u16, ancount: u16, answer: &[u8]) -> Vec<u8> {
        let mut buf = build_query(id, "example.com", RecordType::A).unwrap();
        let flags = 0x8180u16 | rcode;
        buf[2..4].copy_from_slice(&flags.to_be_bytes());
        buf[6..8].copy_from_slice(&ancount.to_be_bytes());
        buf.extend_from_slice(answer);
        buf
    }

    fn a_answer(ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut v = vec![0xC0, 0x0C, 0, 1, 0, 1]; // вказівник на імʼя, TYPE=A, CLASS=IN
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&[0, 4]);
        v.extend_from_slice(&ip);
        v
    }

    fn aaaa_answer(ip: [u8; 16], ttl: u32) -> Vec<u8> {
        let mut v = vec![0xC0, 0x0C, 0, 28, 0, 1]; // TYPE=AAAA
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&[0, 16]);
        v.extend_from_slice(&ip);
        v
    }

    #[test]
    fn build_query_has_correct_bytes() {
        let q = build_query(0x1234, "google.com", RecordType::A).unwrap();
        let expected: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, // header
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // QNAME
            0, 1, 0, 1, // QTYPE=A, QCLASS=IN
        ];
        assert_eq!(q, expected);
    }

    #[test]
    fn build_query_aaaa_uses_type_28() {
        let q = build_query(1, "a.b", RecordType::AAAA).unwrap();
        let n = q.len();
        assert_eq!(&q[n - 4..], &[0, 28, 0, 1]);
    }

    #[test]
    fn build_query_accepts_trailing_dot() {
        let with_dot = build_query(1, "google.com.", RecordType::A).unwrap();
        let without = build_query(1, "google.com", RecordType::A).unwrap();
        assert_eq!(with_dot, without);
    }

    #[test]
    fn build_query_rejects_empty_label() {
        assert!(matches!(
            build_query(1, "bad..domain", RecordType::A),
            Err(DnsError::InvalidDomain(_))
        ));
    }

    #[test]
    fn build_query_rejects_empty_domain() {
        assert!(matches!(
            build_query(1, "", RecordType::A),
            Err(DnsError::InvalidDomain(_))
        ));
    }

    #[test]
    fn build_query_rejects_too_long_label() {
        let domain = format!("{}.com", "a".repeat(64));
        assert!(matches!(
            build_query(1, &domain, RecordType::A),
            Err(DnsError::InvalidDomain(_))
        ));
    }

    #[test]
    fn parse_a_record() {
        let resp = response_with(7, 0, 1, &a_answer([1, 2, 3, 4], 300));
        let answers = parse_response(&resp, 7).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].address, "1.2.3.4");
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[0].record_type, RecordType::A);
    }

    #[test]
    fn parse_aaaa_record() {
        let mut ip = [0u8; 16];
        ip[0] = 0x20;
        ip[1] = 0x01;
        ip[15] = 1; // 2001::1
        let resp = response_with(7, 0, 1, &aaaa_answer(ip, 60));
        let answers = parse_response(&resp, 7).unwrap();
        assert_eq!(answers[0].address, "2001::1");
        assert_eq!(answers[0].record_type, RecordType::AAAA);
    }

    #[test]
    fn parse_multiple_answers() {
        let mut answer = a_answer([1, 1, 1, 1], 10);
        answer.extend(a_answer([8, 8, 8, 8], 20));
        let resp = response_with(7, 0, 2, &answer);
        let answers = parse_response(&resp, 7).unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[1].address, "8.8.8.8");
    }

    #[test]
    fn parse_empty_answer_section() {
        let resp = response_with(7, 0, 0, &[]);
        assert!(parse_response(&resp, 7).unwrap().is_empty());
    }

    #[test]
    fn parse_nxdomain() {
        let resp = response_with(7, 3, 0, &[]);
        assert!(matches!(
            parse_response(&resp, 7),
            Err(DnsError::ServerError(3))
        ));
    }

    #[test]
    fn parse_id_mismatch() {
        let resp = response_with(7, 0, 0, &[]);
        assert!(matches!(
            parse_response(&resp, 8),
            Err(DnsError::IdMismatch)
        ));
    }

    #[test]
    fn parse_packet_shorter_than_header() {
        assert!(matches!(
            parse_response(&[0u8; 5], 0),
            Err(DnsError::MalformedResponse(_))
        ));
    }

    #[test]
    fn parse_truncated_rdata() {
        let mut resp = response_with(7, 0, 1, &a_answer([1, 2, 3, 4], 300));
        resp.truncate(resp.len() - 2); // відрізаємо частину IP-адреси
        assert!(matches!(
            parse_response(&resp, 7),
            Err(DnsError::MalformedResponse(_))
        ));
    }

    #[test]
    fn parse_rejects_query_packet() {
        // Пакет без прапорця QR (це запит, а не відповідь)
        let q = build_query(7, "example.com", RecordType::A).unwrap();
        assert!(matches!(
            parse_response(&q, 7),
            Err(DnsError::MalformedResponse(_))
        ));
    }
}