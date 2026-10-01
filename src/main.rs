mod error;
mod message;
mod resolver;

use message::RecordType;
use std::time::Duration;

fn main() {
    let domain = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());
    let server = "8.8.8.8";

    for rtype in [RecordType::A, RecordType::AAAA] {
        println!("--- {:?} записи для {} (сервер {}) ---", rtype, domain, server);
        match resolver::resolve(server, &domain, rtype, Duration::from_secs(3)) {
            Ok(answers) if answers.is_empty() => println!("Записів не знайдено"),
            Ok(answers) => {
                for a in answers {
                    println!("{:?}\t{}\tTTL={}", a.record_type, a.address, a.ttl);
                }
            }
            Err(e) => eprintln!("Помилка: {e}"),
        }
    }
}