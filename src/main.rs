mod error;
mod message;
mod resolver;

use clap::{Parser, ValueEnum};
use message::RecordType;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum QueryType {
    A,
    Aaaa,
    All,
}

/// Утиліта для розв'язання DNS-запитів (A та AAAA записи)
#[derive(Parser, Debug)]
#[command(name = "dns_resolver", version, about)]
struct Cli {
    /// Один або кілька доменів для розв'язання
    #[arg(required = true)]
    domains: Vec<String>,

    /// IP-адреса DNS-сервера
    #[arg(short, long, default_value = "8.8.8.8")]
    server: String,

    /// Тип запису
    #[arg(short = 't', long = "type", value_enum, default_value = "all")]
    query_type: QueryType,

    /// Таймаут очікування відповіді (секунди)
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// Кількість спроб при відсутності відповіді
    #[arg(short, long, default_value_t = 3)]
    retries: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let types: Vec<RecordType> = match cli.query_type {
        QueryType::A => vec![RecordType::A],
        QueryType::Aaaa => vec![RecordType::AAAA],
        QueryType::All => vec![RecordType::A, RecordType::AAAA],
    };

    let timeout = Duration::from_secs(cli.timeout);
    let mut had_error = false;

    for domain in &cli.domains {
        println!("=== {} (сервер {}) ===", domain, cli.server);
        let mut found_any = false;
        let mut last_error = None;
        let mut error_count = 0;

        for &rtype in &types {
            match resolver::resolve_with_retries(&cli.server, domain, rtype, timeout, cli.retries) {
                Ok(answers) => {
                    for a in answers {
                        found_any = true;
                        println!("{:<5} {:<40} TTL={}", format!("{:?}", a.record_type), a.address, a.ttl);
                    }
                }
                Err(e) => {
                    error_count += 1;
                    last_error = Some(e);
                }
            }
        }

        // Якщо всі запити завершилися помилкою, показуємо її один раз
        if error_count == types.len() {
            if let Some(e) = last_error {
                eprintln!("Помилка: {e}");
            }
            had_error = true;
        } else if !found_any {
            println!("Записів не знайдено");
        }
        println!();
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}