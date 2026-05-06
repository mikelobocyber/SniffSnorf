# 🐽 SniffSnorf

**Async port scanner with a threat surface analyst built in.**

Most port scanners tell you *what* is open. SniffSnorf tells you *what it means*.

After scanning, the analyst engine reads the results the way a human analyst would — it fingerprints the host type, flags dangerous exposures in plain English, and maps every finding to a MITRE ATT&CK technique. Drop the output straight into a pentest report.

```
sniffsnorf -a 192.168.1.1 -p 1-1024
```

```
  ███████╗███╗   ██╗██╗███████╗███████╗███████╗███╗   ██╗ ██████╗ ██████╗ ███████╗
  ...

🐽 1 host · 1024 ports · 1024 total probes · concurrency 500

  HOST                 PORT    SERVICE            STATE
  ─────────────────────────────────────────────────────────────────────────────────
  192.168.1.1          22      ssh                open
  192.168.1.1          80      http               open
  192.168.1.1          3306    mysql              open
  192.168.1.1          6379    redis              open

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐽 SNIFFSNORF ANALYSIS · 192.168.1.1
   Host type: web server
   Surface: 4 open ports
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY
192.168.1.1 has 4 open ports and appears to be a web server.
2 high-severity findings present elevated risk.

FINDINGS

  [1]  HIGH  MySQL database port exposed (port 3306)
       Ports:  3306
       MITRE:  T1190
       Detail: MySQL (port 3306) is reachable from the network. Databases
               should never be directly exposed...

  [2]  HIGH  Redis database port exposed (port 6379)
       Ports:  6379
       MITRE:  T1190
       Detail: Redis has no authentication by default and allows arbitrary
               data reads, writes, and in some configurations remote code
               execution via CONFIG SET...
```

---

## Install

```bash
git clone https://github.com/mikelobocyber/sniffsnorf
cd sniffsnorf
cargo build --release
./target/release/sniffsnorf --help
```

Requires Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`).

---

## Usage

```
sniffsnorf [OPTIONS] <TARGET>

Arguments:
  <TARGET>    IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)

Options:
  -p, --ports <PORTS>         Port or port range [default: 1-1024]
  -c, --concurrency <N>       Max concurrent connections [default: 500]
  -t, --timeout-ms <MS>       Connect timeout per port in ms [default: 1000]
  -b, --banner                Grab service banners from open ports
  -a, --analyze               Run analyst engine (implies --banner)
  -j, --json                  Output results as newline-delimited JSON
  -q, --open-only             Only print open ports
  -h, --help                  Print help
```

---

## Examples

```bash
# Basic scan — top 1024 ports
sniffsnorf 192.168.1.1

# Full analyst report — the main feature
sniffsnorf -a 192.168.1.1

# Analyst on a subnet — reports one host per IP with open ports
sniffsnorf -a 192.168.1.0/24 -p 22,80,443,3306,5432,6379

# Common attack-surface ports with banners
sniffsnorf -b -p 21,22,23,25,80,443,445,3306,3389,5432,5900,6379,8080,27017 192.168.1.1

# Fast full-range scan
sniffsnorf -p 1-65535 -c 2000 -t 500 10.0.0.1

# JSON output for piping to jq
sniffsnorf -j -p 1-1024 192.168.1.1 | jq 'select(.open == true)'

# JSON with analyst findings (human report to stderr, JSON to stdout)
sniffsnorf -a -j 192.168.1.1
```

---

## How the analyst works

After scanning completes, the analyst engine runs three passes over the results:

**1. Host fingerprinting** (`analyst.rs: fingerprint_host`)

Looks at the *combination* of open ports to decide what kind of host this probably is. A host with ports 445 + 139 + 135 is a Windows machine. A host with 2375 open is a Docker host. A host with 3306 + 5432 + no web ports is a database server. The fingerprint drives the narrative tone.

**2. Finding detection** (`analyst.rs: check_*`)

Each detector checks for one specific condition and returns a severity-tagged finding with a plain-English explanation. Detectors cover:

| Finding | Severity | MITRE |
|---|---|---|
| Telnet open | Critical | T1021.004 |
| Docker API without TLS | Critical | T1610 |
| Port 4444 (Metasploit default) | Critical | T1571 |
| RDP exposed | High | T1021.001 |
| SMB exposed (EternalBlue surface) | High | T1021.002 |
| Database ports exposed | High | T1190 |
| Jupyter Notebook exposed | High | T1059 |
| Kubernetes API exposed | High | T1613 |
| FTP open | Medium | T1048.003 |
| SNMP open | Medium | T1602.001 |
| VNC exposed | Medium | T1021.005 |
| Unencrypted LDAP | Medium | T1552.004 |
| SSH present | Low | T1021.004 |
| HTTP without HTTPS | Low | T1557 |
| Dev ports exposed | Low | T1190 |

**3. Banner analysis** (`analyst.rs: check_banner_issues`)

Inspects the actual text received from open ports. Catches things like outdated OpenSSH versions (pre-8.x), FTP anonymous login hints in the welcome banner, SMTP open relay indicators, and web server version disclosure in HTTP headers.

---

## Architecture

```
src/
├── main.rs       CLI (clap), orchestration, task spawning, semaphore concurrency
├── scanner.rs    Async TCP connect, ScanResult struct, port→service name map
├── banner.rs     Banner grabbing — passive read or HTTP HEAD probe
├── cidr.rs       CIDR expansion (IPv4, /16–/32), hostname passthrough
├── output.rs     Colored table + NDJSON rendering
└── analyst.rs    Host fingerprinting, finding detectors, narrative engine
```

### Concurrency model

SniffSnorf spawns one `tokio::spawn` task per (host, port) pair immediately. A `tokio::sync::Semaphore` with `--concurrency` permits ensures at most N connections are in-flight at any time. This avoids the overhead of batching while still respecting the concurrency cap.

### Why Rust?

- Zero-cost async: tokio tasks are not OS threads. Thousands of pending connections use minimal memory.
- No garbage collector: predictable latency on the connect loop.
- `tokio::time::timeout` composes cleanly with `TcpStream::connect` — no callback hell.

---

## MITRE ATT&CK mapping

SniffSnorf findings map to the following ATT&CK tactics:

- **Reconnaissance**: T1592 (host info), T1602 (SNMP)
- **Initial Access**: T1190 (public-facing apps/databases), T1078 (default accounts)
- **Execution**: T1059 (Jupyter), T1610 (container deploy)
- **Lateral Movement**: T1021.001 (RDP), T1021.002 (SMB), T1021.004 (SSH/Telnet), T1021.005 (VNC)
- **Collection**: T1114 (email), T1557 (AitM/no TLS)
- **Exfiltration**: T1048.003 (FTP)
- **Command and Control**: T1571 (non-standard port)

Pair SniffSnorf findings with Wazuh detection rules to build the full attacker/defender picture for your blue-team portfolio.

---

## Legal

Only scan networks you own or have explicit written permission to test. Unauthorized port scanning may violate the CFAA, Computer Misuse Act, and equivalent laws in your jurisdiction.

---

## Author

[github.com/mikelobocyber](https://github.com/mikelobocyber)
