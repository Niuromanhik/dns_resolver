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