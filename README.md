# 🐽 SniffSnorf

**Async port scanner with a threat surface analyst built in.**

Most port scanners tell you *what* is open. SniffSnorf tells you *what it means*.

After scanning, the analyst engine reads the results the way a human analyst would — it fingerprints the host type, flags dangerous exposures in plain English, and maps every finding to a MITRE ATT&CK technique. Save the output as a styled HTML report, plain text, or JSON, and open it instantly from the same command.

```
sniffsnorf -a 192.168.1.1 -o report.html --open
```

---

## Install

```bash
git clone https://github.com/mikelobocyber/SniffSnorf
cd SniffSnorf
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
  -q, --open-only             Only print open ports
  -j, --json                  Output results as newline-delimited JSON
  -o, --output <FILE>         Save output to a file (see Output Formats below)
      --open                  Open the output file after writing (requires -o)
  -h, --help                  Print help
```

---

## Examples

```bash
# Basic scan — top 1024 ports, terminal only
sniffsnorf 192.168.1.1

# Full analyst report in the terminal
sniffsnorf -a 192.168.1.1

# Analyst on a subnet
sniffsnorf -a 192.168.1.0/24 -p 22,80,443,3306,5432,6379

# Common attack-surface ports with banners
sniffsnorf -b -p 21,22,23,25,80,443,445,3306,3389,5432,5900,6379,8080,27017 192.168.1.1

# Fast full-range scan
sniffsnorf -p 1-65535 -c 2000 -t 500 10.0.0.1

# JSON output for piping to jq
sniffsnorf -j -p 1-1024 192.168.1.1 | jq 'select(.open == true)'
```

---

## Output Formats

SniffSnorf prints everything to the terminal by default. Nothing is written to disk unless you ask for it with `-o`. The file extension you give determines the format — no extra flags needed.

### HTML report

```bash
sniffsnorf -a 192.168.1.1 -o report.html
```

Generates a self-contained single-file HTML report with:

- Dark-themed, browser-ready styling with no external dependencies
- Summary stats (open ports, hosts analyzed, total findings)
- Full port table with service and banner columns
- Per-host analyst sections with severity-color-coded findings
- Clickable MITRE ATT&CK links that go directly to `attack.mitre.org`
- Severity summary bar per host (Critical / High / Medium / Low / Info counts)

Open the file by dragging it into any browser, or use `--open` to launch it automatically (see below).

### Plain text

```bash
sniffsnorf -a 192.168.1.1 -o report.txt
```

The same report as the terminal output but with no ANSI color codes — clean for attaching to tickets, emails, or paste bins. Includes the port table and the full analyst narrative with MITRE tags.

### JSON

```bash
sniffsnorf -a 192.168.1.1 -o report.json
```

Newline-delimited JSON (NDJSON), one object per port result. Same format as `-j` to stdout but written to a file. Pipe-friendly and easy to ingest into SIEM rules, scripts, or Wazuh.

Example line:
```json
{"host":"192.168.1.1","port":22,"open":true,"service":"ssh","banner":"SSH-2.0-OpenSSH_9.3","latency_ms":4}
```

---

## Opening Files Automatically

Add `--open` to any command that writes a file and SniffSnorf will launch it in your default application after saving — browser for HTML, text editor for `.txt`, and so on.

```bash
# Scan, generate HTML report, open in browser — all in one command
sniffsnorf -a 192.168.1.1 -o report.html --open
```

How it works per platform:

| Platform | Command used     |
|----------|-----------------|
| Linux    | `xdg-open`      |
| macOS    | `open`          |
| Windows  | `cmd /C start`  |

`--open` has no effect without `-o`. If you forget `-o`, SniffSnorf will warn you rather than silently do nothing.

---

## Saving Files — Full Workflow

**No output flag = nothing written to disk.** SniffSnorf only creates files when you explicitly ask. There are no temp files, no auto-generated junk, and no cleanup step.

A typical workflow for a pentest or blue team exercise:

```bash
# 1. Quick terminal check first — nothing saved
sniffsnorf -a 192.168.1.1

# 2. Happy with the scan? Save the HTML and open it
sniffsnorf -a 192.168.1.1 -o 192-168-1-1.html --open

# 3. Also want machine-readable output for your SIEM
sniffsnorf -a 192.168.1.1 -o 192-168-1-1.json

# 4. Need plain text for a report attachment
sniffsnorf -a 192.168.1.1 -o 192-168-1-1.txt
```

Files are written to whatever directory you ran the command from. Use a dedicated folder to keep scans organized:

```bash
mkdir -p ~/scans/2026-05-16
cd ~/scans/2026-05-16
sniffsnorf -a 192.168.1.0/24 -o subnet-scan.html --open
```

---

## How the Analyst Works

After scanning completes, the analyst engine runs three passes over the results:

**1. Host fingerprinting** (`analyst.rs: fingerprint_host`)

Looks at the combination of open ports to decide what kind of host this probably is. A host with ports 445 + 139 + 135 is a Windows machine. A host with 2375 open is a Docker host. A host with 3306 + 5432 + no web ports is a database server. The fingerprint drives the narrative tone.

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
├── main.rs       CLI (clap), orchestration, task spawning, output routing
├── scanner.rs    Async TCP connect, ScanResult struct, port-to-service name map
├── banner.rs     Banner grabbing — passive read or HTTP HEAD probe
├── cidr.rs       CIDR expansion (IPv4, /16-/32), hostname passthrough
├── output.rs     Terminal table, NDJSON, plain text, and HTML rendering
└── analyst.rs    Host fingerprinting, finding detectors, narrative engine
```

### Output routing

`main.rs` detects the format from the file extension passed to `-o` and routes accordingly:

- `.html` / `.htm` → `output::render_html()` — builds the full self-contained HTML document
- `.json` → `output::render_json_string()` — NDJSON, same schema as `-j` to stdout
- `.txt` or no recognized extension → `output::render_table_plain()` + `analyst::render_report_plain()`

The terminal output always runs regardless of `-o`. Writing a file does not suppress the terminal report.

### Concurrency model

SniffSnorf spawns one `tokio::spawn` task per (host, port) pair immediately. A `tokio::sync::Semaphore` with `--concurrency` permits ensures at most N connections are in-flight at any time. This avoids the overhead of batching while still respecting the concurrency cap.

### Why Rust?

- Zero-cost async: tokio tasks are not OS threads. Thousands of pending connections use minimal memory.
- No garbage collector: predictable latency on the connect loop.
- `tokio::time::timeout` composes cleanly with `TcpStream::connect` — no callback hell.

---

## MITRE ATT&CK Mapping

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
