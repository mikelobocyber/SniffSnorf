// ============================================================
// output.rs — Result rendering
//
// This module takes a slice of ScanResults and renders them
// either as a colored terminal table or as newline-delimited JSON.
//
// Two public functions:
//   print_table(results, open_only) — human-readable colored output
//   print_json(results)             — NDJSON for piping into jq
// ============================================================

use colored::*;
use crate::scanner::ScanResult;


// ============================================================
// print_table
//
// Renders results as a colored, aligned terminal table.
//
// Open ports are printed in full color with service and banner.
// Closed ports are dimmed and shown without banner (less noise).
//
// If `open_only` is true, closed ports are filtered out entirely.
//
// Arguments:
//   results    — the full list of ScanResults from main.rs
//   open_only  — if true, skip printing closed/filtered ports
// ============================================================
pub fn print_table(results: &[ScanResult], open_only: bool) {

    // Filter the results based on the --open-only flag.
    // We collect references (&ScanResult) so we don't clone the data.
    let to_show: Vec<&ScanResult> = results
        .iter()
        .filter(|r| !open_only || r.is_open)  // Keep all, or only open
        .collect();

    // Handle the case where nothing matched
    if to_show.is_empty() {
        println!("{}", "  no open ports found".truecolor(120, 120, 120));
        return;
    }

    // --------------------------------------------------------
    // Print the table header.
    //
    // `{:<20}` means: left-align in a field 20 characters wide.
    // This padding ensures the columns line up even when host
    // names and service names are different lengths.
    //
    // `.truecolor(r, g, b)` from the `colored` crate — sets an
    // exact RGB terminal color on the string.
    // --------------------------------------------------------
    println!(
        "  {:<20} {:<7} {:<18} {:<10} {}",
        "HOST".truecolor(160, 160, 160),
        "PORT".truecolor(160, 160, 160),
        "SERVICE".truecolor(160, 160, 160),
        "STATE".truecolor(160, 160, 160),
        "BANNER".truecolor(160, 160, 160),
    );

    // A horizontal divider line — dim to not compete with data
    println!("  {}", "─".repeat(80).truecolor(60, 60, 60));

    // --------------------------------------------------------
    // Print each result row.
    //
    // We use different formatting for open vs closed:
    //   Open:   full color, includes service name and banner
    //   Closed: dimmed gray, no banner column (less visual noise)
    // --------------------------------------------------------
    for r in to_show {

        // Format the state badge
        // `.green().bold()` chains color + weight modifiers from `colored`
        let state = if r.is_open {
            "open".green().bold()
        } else {
            // `into()` converts the colored string to the common return type
            "closed".truecolor(80, 80, 80).into()
        };

        // Format the service name, or a dim dash if unknown
        // `Option::map` transforms Some(x) → Some(f(x)), leaves None as None
        let service = r
            .service
            .map(|s| s.cyan().to_string())
            .unwrap_or_else(|| "-".truecolor(80, 80, 80).to_string());

        // Format the banner, or empty string if none
        let banner = r
            .banner
            .as_deref()  // Convert Option<String> → Option<&str>
            .map(|b| b.truecolor(200, 200, 140).to_string())
            .unwrap_or_default();  // "" if None

        if r.is_open {
            // Full row for open ports
            println!(
                "  {:<20} {:<7} {:<28} {:<20} {}",
                r.host.white(),
                r.port.to_string().yellow().bold(),
                service,
                state,
                banner,
            );
        } else {
            // Shorter, dimmer row for closed ports
            println!(
                "  {:<20} {:<7} {:<18} {}",
                r.host.truecolor(80, 80, 80),
                r.port.to_string().truecolor(80, 80, 80),
                "-".truecolor(60, 60, 60),
                state,
            );
        }
    }
}


// ============================================================
// print_json
//
// Prints one JSON object per line (NDJSON / JSON Lines format).
//
// Why NDJSON and not a single JSON array?
//   - You can stream it: results appear as they're processed
//   - `jq` works on it line-by-line without loading the whole file
//   - Easy to append to a file across multiple runs
//
// Example output line:
//   {"host":"192.168.1.1","port":22,"open":true,"service":"ssh","banner":"SSH-2.0-OpenSSH_8.9","latency_ms":3}
//
// We hand-build the JSON strings instead of pulling in a serde
// dependency — keeps the scaffolding lean. You can swap this for
// serde_json later by adding it to Cargo.toml and deriving Serialize.
// ============================================================
pub fn print_json(results: &[ScanResult]) {
    for r in results {

        // Format service: either a quoted string or JSON null
        let service = r
            .service
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".to_string());

        // Format banner: either a quoted, escaped string or JSON null.
        // We escape internal quotes to keep the JSON valid.
        let banner = r
            .banner
            .as_deref()
            .map(|b| format!("\"{}\"", b.replace('"', "\\\"")))
            .unwrap_or_else(|| "null".to_string());

        // Print the full JSON object on one line.
        // `println!` adds the newline — that's what makes it NDJSON.
        println!(
            "{{\"host\":\"{}\",\"port\":{},\"open\":{},\"service\":{},\"banner\":{},\"latency_ms\":{}}}",
            r.host,
            r.port,
            r.is_open,   // Rust bool prints as "true"/"false" — valid JSON
            service,
            banner,
            r.latency_ms,
        );
    }
}
