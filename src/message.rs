use crate::error::DnsError;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::CNAME => 5,
        }
    }
}

#[derive(Debug)]
pub struct Answer {
    pub name: String,
    pub address: String,
    pub record_type: RecordType,
    pub ttl: u32,
}

/// Будує DNS-запит.
pub fn build_query(id: u16, domain: &str, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::with_capacity(512);

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
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

/// Читає доменне імʼя з урахуванням стиснення.
/// Повертає (імʼя, позиція після імені в поточному місці пакета).
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut end_pos: Option<usize> = None;
    let mut jumps = 0;
    let mut labels: Vec<String> = Vec::new();

    loop {
        let len = *buf
            .get(pos)
            .ok_or(DnsError::MalformedResponse("неочікуваний кінець пакета"))?;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let b2 = *buf
                .get(pos + 1)
                .ok_or(DnsError::MalformedResponse("неочікуваний кінець пакета"))?;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 20 {
                return Err(DnsError::MalformedResponse("цикл у вказівниках стиснення"));
            }
            pos = (((len & 0x3F) as usize) << 8) | b2 as usize;
            continue;
        }
        let label = buf
            .get(pos + 1..pos + 1 + len as usize)
            .ok_or(DnsError::MalformedResponse("мітка виходить за межі пакета"))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len as usize;
    }

    Ok((labels.join("."), end_pos.unwrap_or(pos)))
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
        let (_, next) = read_name(buf, pos)?;
        pos = next + 4;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (name, next) = read_name(buf, pos)?;
        pos = next;
        let rtype = read_u16(buf, pos)?;
        let ttl = read_u32(buf, pos + 4)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;

        let data = buf
            .get(pos..pos + rdlen)
            .ok_or(DnsError::MalformedResponse("RDATA виходить за межі пакета"))?;

        match (rtype, rdlen) {
            (1, 4) => answers.push(Answer {
                name,
                address: Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
                record_type: RecordType::A,
                ttl,
            }),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                answers.push(Answer {
                    name,
                    address: Ipv6Addr::from(octets).to_string(),
                    record_type: RecordType::AAAA,
                    ttl,
                });
            }
            (5, _) => {
                let (target, _) = read_name(buf, pos)?;
                answers.push(Answer {
                    name,
                    address: target,
                    record_type: RecordType::CNAME,
                    ttl,
                });
            }
            _ => {}
        }
        pos += rdlen;
    }
    Ok(answers)
}

    #[test]
    fn parse_cname_record() {
        // CNAME "www.example.com" -> "example.com": RDATA це імʼя у форматі міток
        let mut rdata = vec![7];
        rdata.extend_from_slice(b"example");
        rdata.extend_from_slice(&[3, b'c', b'o', b'm', 0]);

        let mut answer = vec![0xC0, 0x0C, 0, 5, 0, 1]; // TYPE=CNAME
        answer.extend_from_slice(&300u32.to_be_bytes());
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(&rdata);

        let resp = response_with(7, 0, 1, &answer);
        let answers = parse_response(&resp, 7).unwrap();
        assert_eq!(answers[0].record_type, RecordType::CNAME);
        assert_eq!(answers[0].address, "example.com");
        assert_eq!(answers[0].name, "example.com");
    }

    #[test]
    fn parse_rejects_compression_loop() {
        // Вказівник стиснення, що посилається сам на себе
        let mut buf = build_query(7, "example.com", RecordType::A).unwrap();
        buf[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        let loop_pos = buf.len();
        buf.extend_from_slice(&[0xC0, loop_pos as u8]); // вказує сам на себе
        assert!(matches!(
            parse_response(&buf, 7),
            Err(DnsError::MalformedResponse(_))
        ));
    }