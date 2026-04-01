# axios-incident-check-rs

A fast, terminal-based scanner that checks whether a developer machine is affected by the [axios supply-chain attack](https://socket.dev/blog/axios-npm-supply-chain-attack) (malicious axios versions **1.14.1** and **0.30.4**).

Built in Rust with a TUI powered by [ratatui](https://ratatui.rs). Scans lockfiles, `node_modules`, temp directories, shell history, system logs, and live processes for known indicators of compromise (IOCs).

![screenshot](https://img.shields.io/badge/platform-linux%20%7C%20macOS-blue)

## Quick Start (one-liner)

**Linux (x86_64):**

```bash
curl -fsSL https://github.com/sevsev9/axios-incident-check-rs/releases/latest/download/axios-incident-check-rs-x86_64-unknown-linux-musl.tar.gz | tar xz && ./axios-incident-check-rs
```

**Linux (aarch64):**

```bash
curl -fsSL https://github.com/sevsev9/axios-incident-check-rs/releases/latest/download/axios-incident-check-rs-aarch64-unknown-linux-musl.tar.gz | tar xz && ./axios-incident-check-rs
```

**macOS (Apple Silicon):**

```bash
curl -fsSL https://github.com/sevsev9/axios-incident-check-rs/releases/latest/download/axios-incident-check-rs-aarch64-apple-darwin.tar.gz | tar xz && ./axios-incident-check-rs
```

**macOS (Intel):**

```bash
curl -fsSL https://github.com/sevsev9/axios-incident-check-rs/releases/latest/download/axios-incident-check-rs-x86_64-apple-darwin.tar.gz | tar xz && ./axios-incident-check-rs
```

## What It Checks

| Check | What it looks for |
|---|---|
| **Lockfiles & manifests** | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `package.json` referencing axios `1.14.1` / `0.30.4` or known malicious dependencies |
| **node_modules** | Installed `plain-crypto-js`, `@shadanai/openclaw`, `@qqbrowser/openclaw-qbot` directories |
| **IOC files** | `/tmp/ld.py`, `/var/tmp/ld.py`, `/Library/Caches/com.apple.act.mond`, campaign artifacts in `$TMPDIR`, Windows IOC paths in WSL |
| **Shell history & user logs** | npm logs, bash/zsh/fish history for IOC domains, IPs, suspicious URLs |
| **System logs** | `/var/log/syslog`, `auth.log`, `messages`, `dpkg.log` |
| **Live processes** | `ps auxww` output for `ld.py`, `sfrclak`, `plain-crypto-js`, suspicious `python3 nohup` combos |

### Known IOCs

- **Domain:** `sfrclak.com`
- **IP:** `142.11.206.73`
- **C2 URL pattern:** `packages.npm.org/product`
- **Campaign ID:** `6202033`
- **Dropped file (Linux):** `/tmp/ld.py`
- **Dropped file (macOS):** `/Library/Caches/com.apple.act.mond`
- **Malicious packages:** `plain-crypto-js`, `@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`

## Building From Source

Requires Rust 1.85+ (edition 2024).

```bash
git clone https://github.com/sevsev9/axios-incident-check-rs.git
cd axios-incident-check-rs
cargo build --release
./target/release/axios-incident-check-rs
```

## Usage

```
$ ./axios-incident-check-rs
╔══════════════════════════════════════════╗
║      Axios Incident Scanner (v0.1.0)     ║
╚══════════════════════════════════════════╝

Scan directory [/home/user]: ~/projects
```

On launch you'll be prompted for a directory to scan (defaults to `$HOME`). The TUI then starts and scans in parallel.

### Keyboard Shortcuts

| Key | Action |
|---|---|
| `q` / `Esc` | Quit |
| `j` / `k` or `Up` / `Down` | Navigate sections |
| `Enter` / `Space` | Expand/collapse section |
| `a` | Expand all sections |
| `c` | Collapse all sections |
| `?` / `h` | Toggle help overlay |
| `PgUp` / `PgDn` | Scroll live event log |

## Risk Scoring

| Verdict | Score |
|---|---|
| No strong local indicators found | 0 - 19 |
| Suspicious / needs review | 20 - 49 |
| High risk / strong indicators | 50 - 99 |
| **Likely compromised** | 100+ |

## License

MIT
