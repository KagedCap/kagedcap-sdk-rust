<p align="center"><img src="https://kagedcap.io/kc-logo.svg" width="260" alt="KagedCap"></p>

# KagedCap Rust SDK

Solve reCAPTCHA (v3, v3 Enterprise, v2), Ticketmaster tmpt, and Kasada with a single API
key. Blocking client built on `ureq`.

## Install

```bash
cargo add kagedcap
```

Or in `Cargo.toml`:

```toml
[dependencies]
kagedcap = "0.2"
```

## Quick start

```rust
use kagedcap::{KagedCapClient, SolveParams};

fn main() {
    let kc = KagedCapClient::new(std::env::var("KAGEDCAP_API_KEY").unwrap());

    let res = kc.solve(SolveParams {
        sitekey: "6LcvL3UrAAAAAO_9u8Seiuf-I6F_tP_jSS-zndXV".into(),
        url: "https://www.ticketmaster.com".into(),
        action: "Event".into(),
        // user_agent left unset → kagedcap::DEFAULT_USER_AGENT. Set it to match your own traffic.
        enterprise: true, // ProxyLess Enterprise
        ..Default::default()
    }).unwrap();
    println!("{}", res.token);

    let bal = kc.check_balance().unwrap();
    println!("balance: {}", bal.display);
}
```

## With a proxy

```rust
let res = kc.solve(SolveParams {
    sitekey: "6Lc...".into(),
    url: "https://example.com/login".into(),
    action: "login".into(),
    proxy: Some("http://user:pass@1.2.3.4:8080".into()), // or host:port:user:pass
    ..Default::default()
})?;
```

Leave `proxy` as `None` for a ProxyLess solve. Set `enterprise: true` for Enterprise
sitekeys, or set `task` explicitly.

## User agent

The token embeds the UA it was minted with, so every solve carries one. Leave `user_agent`
as `None` (or empty) and the SDK sends `kagedcap::DEFAULT_USER_AGENT` — the same Chrome
desktop profile the solver fleet runs:

```rust
println!("{}", kagedcap::DEFAULT_USER_AGENT);
// Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
```

Set `user_agent` yourself when your traffic presents a different browser — an explicit value
always wins. Kasada is the exception: it takes no UA at all (see below).

## Kasada

`kasada_login` starts a session (requires a proxy — the token is IP-bound) and returns the
full header set. Keep that result and pass it to `kasada_reload` to refresh the session — the
SDK resends the session's `kpsdk_st`, `hash`, and `x_kpsdk_*` values for you (`hash` + `x_kpsdk_ct` are required).

```rust
use kagedcap::{KagedCapClient, KasadaParams};

let kc = KagedCapClient::new(std::env::var("KAGEDCAP_API_KEY").unwrap());

let login = kc.kasada_login(KasadaParams {
    site: Some("ticketmaster".into()),
    proxy: Some("http://user:pass@1.2.3.4:8080".into()),
    ..Default::default()
})?;
// Replay login.headers (user-agent + sec-ch-ua*) and login.x_kpsdk_* on your request.

let fresh = kc.kasada_reload(&login)?; // no proxy needed
println!("{}", fresh.x_kpsdk_cd);
```

Kasada results have **no `token`** — replay `headers` and the `x_kpsdk_*` values instead.
No user agent is sent on either Kasada call: the harvester picks the identity and reports it
back in `headers` / `user_agent`, so replay that one rather than choosing your own.

## Errors

Failures return `KagedCapError` with `.status`, `.code`, and `.message`. Common
codes: `unauthorized`, `insufficient_funds`, `solve_failed`, `solve_timeout`,
`proxy_required`, `proxy_not_allowed`, `validation_error`, `concurrency_limit_exceeded`, `key_frozen`.

Only successful solves are billed.
