![CI]
(https://github.com/Niuromanhik/dns_resolver/actions/workflows/ci.yml/badge.svg)
# dns_resolver

Консольна утиліта для розв'язання DNS-запитів (A та AAAA записи), написана на Rust.
DNS-протокол (RFC 1035) реалізовано вручну поверх UDP-сокета зі стандартної бібліотеки.

## Можливості

- Відправлення DNS-запитів до вказаного сервера (за замовчуванням 8.8.8.8)
- Відображення IPv4 (A) та IPv6 (AAAA) адрес для домену
- Кілька доменів за один запуск
- Таймаут і повтори при втраті пакета
- Обробка помилок: некоректний домен, NXDOMAIN, SERVFAIL, REFUSED, таймаут, пошкоджена відповідь
- Працює на Windows, macOS та Linux

## Встановлення

Потрібен [Rust](https://rustup.rs) (версія 1.74 або новіша) і Git.

```
git clone https://github.com/Niuromanhik/dns_resolver.git
cd dns_resolver
cargo build --release
```

Виконуваний файл буде в `target/release/dns_resolver` (на Windows `dns_resolver.exe`).

## Використання

```
dns_resolver [OPTIONS] <DOMAINS>...
```

| Параметр | Опис | За замовчуванням |
|---|---|---|
| `-s, --server <IP>` | DNS-сервер | `8.8.8.8` |
| `-t, --type <a\|aaaa\|all>` | Тип запису | `all` |
| `--timeout <СЕК>` | Таймаут очікування відповіді | `3` |
| `-r, --retries <N>` | Кількість спроб | `3` |
| `-h, --help` | Довідка | |

### Приклади

```
dns_resolver google.com
dns_resolver -t aaaa google.com github.com
dns_resolver -s 1.1.1.1 -t a github.com
```

Код виходу: `0` при успіху, `1` якщо хоча б один домен не вдалося розв'язати.

## Структура проєкту

```
src/
├── main.rs       # CLI та вивід результатів
├── message.rs    # побудова запиту, розбір відповіді, юніт-тести
├── resolver.rs   # UDP-обмін, таймаути, повтори
└── error.rs      # тип помилок DnsError
```

## Тестування

```
cargo test
```