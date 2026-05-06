// ============================================================
// banner.rs — Service banner grabbing
//
// When a port is open, we can optionally read the first bytes
// the server sends. Many services announce themselves this way:
//
//   SSH:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
//   FTP:   "220 vsftpd 3.0.5"
//   SMTP:  "220 mail.example.com ESMTP Postfix"
//   Redis: "+PONG"
//
// For protocols that wait for the CLIENT to speak first (HTTP),
// we send a minimal probe to elicit a response.
//
// This module exposes one public function: `grab_banner()`.
// ============================================================

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;


// ============================================================
// probe_for_port
//
// Some protocols are "server speaks first" (SSH, FTP, SMTP) —
// we just open the connection and read whatever arrives.
//
// Other protocols are "client speaks first" (HTTP) — the server
// waits silently until we send a request. For those, we return
// a minimal probe string to send before reading.
//
// Returns:
//   Some(&[u8])  — bytes to send as a probe before reading
//   None         — just listen, server will talk first
//
// `&'static [u8]` means: a byte slice that lives in the binary
// (a compile-time constant), no heap allocation needed.
// ============================================================
fn probe_for_port(port: u16) -> Option<&'static [u8]> {
    match port {
        // HTTP: send a minimal HEAD request.
        // HEAD is like GET but the server only returns headers,
        // not the full body — less data, faster banner.
        80 | 8080 | 8000 | 3000 => Some(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),

        // HTTPS / TLS ports: we'd need to do a TLS handshake first.
        // Plain TCP reads will just get garbled TLS records.
        // Skipping for now — TLS banner grabbing is a future feature.
        443 | 8443 => None,

        // Everything else: server-speaks-first, just read.
        _ => None,
    }
}


// ============================================================
// grab_banner
//
// Attempts to read an identifying string from an open TcpStream.
//
// Arguments:
//   stream        — the already-open TCP connection from scan_port()
//   port          — the port number (used to decide if we probe)
//   read_timeout  — how long to wait for data before giving up
//
// Returns:
//   Some(String)  — a cleaned, printable banner string
//   None          — nothing arrived within the timeout, or error
//
// Why reuse the stream from scan_port() instead of reconnecting?
//   Reconnecting would mean a second TCP handshake — extra latency
//   and an extra entry in the target's connection logs. Reusing
//   the existing stream is faster and quieter.
// ============================================================
pub async fn grab_banner(
    mut stream: TcpStream,
    port: u16,
    read_timeout: Duration,
) -> Option<String> {

    // --------------------------------------------------------
    // Step 1: Send a probe if this protocol needs one.
    //
    // `write_all` is also wrapped in a timeout — we don't want
    // to hang forever if the server's receive buffer is full.
    // --------------------------------------------------------
    if let Some(probe) = probe_for_port(port) {
        // If sending the probe fails or times out, bail early.
        // `is_err()` returns true for both timeout AND write errors.
        if timeout(read_timeout, stream.write_all(probe)).await.is_err() {
            return None;
        }
    }

    // --------------------------------------------------------
    // Step 2: Read the server's response into a buffer.
    //
    // We allocate 1024 bytes — enough for any reasonable banner.
    // `vec![0u8; 1024]` creates a Vec of 1024 zero bytes.
    //
    // `stream.read(&mut buf)` returns Ok(n) where n is the number
    // of bytes actually read. It does NOT fill the buffer — it
    // just reads whatever arrived in one syscall.
    // --------------------------------------------------------
    let mut buf = vec![0u8; 1024];

    let read_result = timeout(read_timeout, stream.read(&mut buf)).await;

    match read_result {
        // Got some bytes (n > 0 means real data, not EOF)
        Ok(Ok(n)) if n > 0 => {
            // Only look at the bytes that were actually filled
            let raw = &buf[..n];

            // Clean up the raw bytes into a printable string
            Some(clean_banner(raw))
        }

        // Anything else: timeout, read error, or EOF (n == 0)
        _ => None,
    }
}


// ============================================================
// clean_banner
//
// Raw TCP bytes can contain anything — control characters,
// null bytes, binary data. This function converts them into
// a clean, single-line, printable string.
//
// What it does:
//   1. Replace newlines and tabs with spaces
//   2. Replace non-printable / non-ASCII bytes with dots
//   3. Collapse multiple spaces into one
//   4. Truncate to 120 characters (fits one terminal line)
// ============================================================
fn clean_banner(raw: &[u8]) -> String {
    // Step 1: Map each byte to a char.
    // `b` is a u8 (byte). We check what kind of byte it is
    // and decide what character to emit.
    let s: String = raw
        .iter()
        .map(|&b| {
            if b == b'\n' || b == b'\r' || b == b'\t' {
                // Newlines and tabs become spaces so the banner
                // stays on one line in our table output.
                ' '
            } else if b.is_ascii_graphic() || b == b' ' {
                // Printable ASCII characters pass through as-is.
                // `is_ascii_graphic()` covers 33–126 (everything
                // printable except space), so we add space back.
                b as char
            } else {
                // Non-printable bytes (control chars, high bytes)
                // become dots — makes binary data visible without
                // breaking the terminal.
                '.'
            }
        })
        .collect();

    // Step 2: Collapse runs of whitespace into single spaces.
    // `split_whitespace()` splits on any whitespace and discards
    // empty chunks. Rejoining with " " gives us clean output.
    let collapsed: String = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // Step 3: Truncate to 120 characters.
    // `len()` is byte length — safe here because we only have ASCII.
    // We append "…" (ellipsis) to show the string was cut.
    if collapsed.len() > 120 {
        format!("{}…", &collapsed[..119])
    } else {
        collapsed
    }
}
