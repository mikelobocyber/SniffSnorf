// ============================================================
// scanner.rs — Core async TCP probe logic
//
// This module owns two things:
//   1. `ScanResult` — the data type that holds the outcome of
//      probing one (host, port) pair
//   2. `scan_port()` — the async function that does the probe
//
// Everything in here is called once per (host, port) pair,
// from inside a tokio::spawn task in main.rs.
// ============================================================

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// We need the banner grabber from banner.rs.
// `crate::banner` refers to our own crate's banner module.
use crate::banner::grab_banner;


// ============================================================
// ScanResult
//
// This struct holds everything we learn about one (host, port)
// probe. It's returned by scan_port() and collected in main.rs.
//
// `#[derive(Debug, Clone)]` auto-generates:
//   - Debug: lets us print it with {:?} during development
//   - Clone: lets us duplicate the struct cheaply (used in output.rs)
// ============================================================
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// The host we probed (IP string or hostname)
    pub host: String,

    /// The port number we probed (u16 = 0–65535)
    pub port: u16,

    /// true if TCP connect succeeded, false if refused or timed out
    pub is_open: bool,

    /// A known service name for this port, if we recognize it
    /// `Option<&'static str>` means: either Some("ssh") or None
    /// `'static` means the string lives for the entire program lifetime
    pub service: Option<&'static str>,

    /// The banner bytes we received after connecting, cleaned up
    /// as a printable string. None if banner grabbing was off or
    /// if the port sent nothing.
    pub banner: Option<String>,

    /// How long the connect attempt took in milliseconds.
    /// Useful for spotting filtered ports (they hit the timeout
    /// ceiling) vs actively refused ports (fast RST response).
    pub latency_ms: u64,
}


// ============================================================
// scan_port
//
// The main probe function. Called once per (host, port) pair.
//
// Arguments:
//   host            — IP address or hostname string
//   port            — port number to probe
//   connect_timeout — how long to wait before giving up
//   do_banner       — whether to try reading the server's opening bytes
//
// Returns a ScanResult either way — open ports and closed ports
// both produce a result. This keeps the code in main.rs simple:
// it just awaits and collects, no special-casing needed.
//
// Why `async fn`? Because `TcpStream::connect` is non-blocking.
// Instead of blocking a thread to wait for the TCP handshake,
// the tokio executor parks this task and works on other tasks
// while the OS completes the connection in the background.
// ============================================================
pub async fn scan_port(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    do_banner: bool,
) -> ScanResult {
    // Format the address as "host:port" — what tokio's connect expects
    let addr = format!("{host}:{port}");

    // Record the start time so we can calculate latency
    let start = std::time::Instant::now();

    // --------------------------------------------------------
    // The actual TCP connect attempt.
    //
    // `tokio::time::timeout` wraps a future and returns:
    //   Ok(inner_result)  — if the future completed in time
    //   Err(Elapsed)      — if the timeout fired first
    //
    // `TcpStream::connect` itself returns:
    //   Ok(TcpStream)     — TCP handshake succeeded (port is open)
    //   Err(io::Error)    — connection refused, host unreachable, etc.
    //
    // So `connect_result` is: Result<Result<TcpStream, io::Error>, Elapsed>
    // We match on the outer Ok vs Err first.
    // --------------------------------------------------------
    let connect_result = timeout(connect_timeout, TcpStream::connect(&addr)).await;

    // Measure how long the attempt took
    let latency_ms = start.elapsed().as_millis() as u64;

    match connect_result {
        // Outer Ok = didn't time out. Inner Ok = connection succeeded.
        Ok(Ok(stream)) => {
            // Port is open! Optionally try to grab the banner.
            // We pass the live stream directly — no second connection.
            let banner = if do_banner {
                grab_banner(stream, port, Duration::from_millis(2000)).await
            } else {
                None
            };

            ScanResult {
                host: host.to_string(),
                port,
                is_open: true,
                service: common_service(port),  // Look up the known service name
                banner,
                latency_ms,
            }
        }

        // Any other outcome = port is not open.
        // This covers:
        //   Ok(Err(_))  — connection refused (fast RST from the host)
        //   Err(_)      — timed out (port may be filtered by firewall)
        _ => ScanResult {
            host: host.to_string(),
            port,
            is_open: false,
            service: common_service(port),
            banner: None,
            latency_ms,
        },
    }
}


// ============================================================
// common_service
//
// Maps well-known port numbers to their IANA service names.
// Returns None for ports we don't recognize.
//
// This is a simple lookup table — a `match` expression in Rust
// is compiled to a jump table by the compiler, so it's O(1).
//
// Why `&'static str` and not `String`?
//   These are string literals baked into the binary at compile
//   time. They don't need to be allocated on the heap. `'static`
//   is the lifetime that means "lives as long as the program."
// ============================================================
pub fn common_service(port: u16) -> Option<&'static str> {
    match port {
        // -- File Transfer --
        20    => Some("ftp-data"),
        21    => Some("ftp"),
        69    => Some("tftp"),

        // -- Remote Access --
        22    => Some("ssh"),
        23    => Some("telnet"),
        3389  => Some("rdp"),
        5900  => Some("vnc"),

        // -- Mail --
        25    => Some("smtp"),
        110   => Some("pop3"),
        143   => Some("imap"),
        465   => Some("smtps"),
        587   => Some("smtp-sub"),
        993   => Some("imaps"),
        995   => Some("pop3s"),

        // -- Web --
        80    => Some("http"),
        443   => Some("https"),
        8080  => Some("http-alt"),
        8443  => Some("https-alt"),
        8888  => Some("jupyter"),
        3000  => Some("dev-http"),

        // -- DNS / Network Infrastructure --
        53    => Some("dns"),
        67    => Some("dhcp"),
        68    => Some("dhcp"),
        123   => Some("ntp"),
        161   => Some("snmp"),
        162   => Some("snmp-trap"),
        179   => Some("bgp"),

        // -- Windows / SMB --
        135   => Some("msrpc"),
        137   => Some("netbios-ns"),
        139   => Some("netbios-ssn"),
        445   => Some("smb"),

        // -- Directory / Auth --
        389   => Some("ldap"),
        636   => Some("ldaps"),

        // -- Databases --
        1433  => Some("mssql"),
        1521  => Some("oracle"),
        3306  => Some("mysql"),
        5432  => Some("postgres"),
        6379  => Some("redis"),
        9200  => Some("elasticsearch"),
        9300  => Some("elasticsearch-t"),
        27017 => Some("mongodb"),

        // -- Messaging / Coordination --
        194   => Some("irc"),
        2181  => Some("zookeeper"),

        // -- Container / Cloud --
        2375  => Some("docker"),
        2376  => Some("docker-tls"),
        6443  => Some("k8s-api"),

        // -- VPN / Proxy --
        1080  => Some("socks"),
        1194  => Some("openvpn"),
        1723  => Some("pptp"),

        // -- Misc Services --
        119   => Some("nntp"),
        515   => Some("lpd"),
        514   => Some("syslog"),
        631   => Some("ipp"),
        2049  => Some("nfs"),
        5000  => Some("upnp"),

        // -- Commonly targeted / red-team relevant --
        4444  => Some("metasploit"),   // Default Metasploit handler port

        // Any port we don't recognize
        _     => None,
    }
}
