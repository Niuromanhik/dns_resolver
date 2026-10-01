use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    Io(std::io::Error),
    InvalidDomain(String),
    Timeout,
    MalformedResponse(&'static str),
    ServerError(u8),
    IdMismatch,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Io(e) => write!(f, "Помилка мережі: {e}"),
            DnsError::InvalidDomain(d) => write!(f, "Некоректне доменне імʼя: {d}"),
            DnsError::Timeout => write!(f, "Сервер не відповів вчасно"),
            DnsError::MalformedResponse(m) => write!(f, "Пошкоджена відповідь: {m}"),
            DnsError::ServerError(code) => match code {
                1 => write!(f, "Сервер: помилка формату запиту (FORMERR)"),
                2 => write!(f, "Сервер: збій сервера (SERVFAIL)"),
                3 => write!(f, "Домен не існує (NXDOMAIN)"),
                4 => write!(f, "Сервер: тип запиту не підтримується (NOTIMP)"),
                5 => write!(f, "Сервер відхилив запит (REFUSED)"),
                c => write!(f, "Сервер повернув код помилки {c}"),
            },
            DnsError::IdMismatch => write!(f, "ID відповіді не збігається з ID запиту"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => DnsError::Timeout,
            _ => DnsError::Io(e),
        }
    }
}