// ============================================================
// main.rs — SniffSnorf entry point
//
// This file does three things:
//   1. Defines the CLI flags using clap's `derive` macro
//   2. Orchestrates the scan (resolves targets, spawns tasks,
//      collects results, hands off to output)
//   3. Prints the ASCII banner on startup
//
// The `mod` declarations below tell Rust to look for sibling
// files (scanner.rs, banner.rs, etc.) in the same `src/` folder.
// ============================================================

mod analyst;  // Threat surface narration — the thing that makes SniffSnorf different
mod banner;   // Banner grabbing — reads first bytes from open ports
mod cidr;     // CIDR expansion and target resolution
mod output;   // Table and JSON rendering
mod scanner;  // Core async TCP connect logic

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;

// Bring ScanResult into scope so we can use it in main without
// writing `scanner::ScanResult` everywhere.
use crate::scanner::ScanResult;


// ============================================================
// CLI definition
//
// `#[derive(Parser)]` tells clap to auto-generate argument
// parsing code from this struct. Each field becomes a flag.
// `#[arg(...)]` attributes configure each flag's name, default,
// and help text.
// ============================================================

/// SniffSnorf — async port scanner with banner grabbing and CIDR support
#[derive(Parser, Debug)]
#[command(
    name = "sniffsnorf",
    about = "SniffSnorf 🐽 — async port scanner",
    long_about = None
)]
pub struct Args {
    /// Target: IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)
    #[arg(required = true)]
    pub target: String,

    /// Port or port range — supports singles, ranges, and comma lists
    /// Examples: 80    22-443    22,80,443    1-1024
    #[arg(short, long, default_value = "1-1024")]
    pub ports: String,

    /// Maximum number of simultaneous TCP connections.
    /// Higher = faster scan; lower = quieter / more polite.
    #[arg(short, long, default_value = "500")]
    pub concurrency: usize,

    /// How long to wait for a connection before marking port closed (milliseconds)
    #[arg(short, long, default_value = "1000")]
    pub timeout_ms: u64,

    /// If set, attempt to read the opening bytes from each open port
    /// to identify the service (SSH version string, HTTP headers, etc.)
    #[arg(short, long)]
    pub banner: bool,

    /// Print results as newline-delimited JSON instead of a human table.
    /// Useful for piping into `jq` or saving for later analysis.
    #[arg(short, long)]
    pub json: bool,

    /// Hide closed/filtered ports — only print open ones.
    #[arg(short = 'q', long)]
    pub open_only: bool,

    /// Run the analyst engine after scanning: narrate what was found,
    /// flag dangerous exposures, and map findings to MITRE ATT&CK.
    /// Automatically enables banner grabbing for richer analysis.
    #[arg(short = 'a', long)]
    pub analyze: bool,
}


// ============================================================
// main — async entry point
//
// `#[tokio::main]` is a macro that wraps our async fn in the
// tokio runtime setup boilerplate. Without it, `async fn main`
// isn't valid Rust — someone has to build and run the executor.
// ============================================================

#[tokio::main]
async fn main() {
    // Parse CLI arguments. clap will exit with a help message
    // automatically if required args are missing or flags are wrong.
    let args = Args::parse();

    // Print the ASCII logo at the top of every run.
    print_logo();

    // --------------------------------------------------------
    // Step 1: Resolve the target string into a list of IPs.
    //
    // "192.168.1.1"     → ["192.168.1.1"]
    // "192.168.1.0/24"  → ["192.168.1.0", "192.168.1.1", ..., "192.168.1.255"]
    // "scanme.nmap.org" → ["scanme.nmap.org"]  (DNS resolved at connect time)
    // --------------------------------------------------------
    let targets = match crate::cidr::resolve_targets(&args.target) {
        Ok(t) => t,
        Err(e) => {
            // `.red().bold()` from the `colored` crate — makes terminal output red.
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    // --------------------------------------------------------
    // Step 2: Parse the port string into a sorted Vec<u16>.
    //
    // "22,80,443"  → [22, 80, 443]
    // "1-1024"     → [1, 2, 3, ..., 1024]
    // --------------------------------------------------------
    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    // Total number of probes = hosts × ports.
    // This drives the progress bar and the opening summary line.
    let total = targets.len() as u64 * ports.len() as u64;

    println!(
        "{} {} host(s) · {} port(s) · {} total probes · concurrency {}\n",
        "🐽".bold(),
        targets.len().to_string().white().bold(),
        ports.len().to_string().white().bold(),
        total.to_string().white().bold(),
        args.concurrency.to_string().yellow(),
    );

    // If --analyze is set, we need banners for richer analysis.
    // Override the banner flag so the user doesn't have to type both.
    let grab_banner = args.banner || args.analyze;

    // --------------------------------------------------------
    // Step 3: Set up the progress bar.
    //
    // `ProgressBar::new(total)` creates a bar that goes from 0
    // to `total`. We call `.inc(1)` inside each scan task when
    // it finishes, so the bar advances in real time.
    // --------------------------------------------------------
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    // --------------------------------------------------------
    // Step 4: Create the Semaphore that caps concurrency.
    //
    // A Semaphore has N permits. Each task must acquire one
    // permit before starting its TCP connect, and the permit is
    // automatically released when it goes out of scope.
    //
    // This means at most `args.concurrency` connections can be
    // in-flight at the same time, even though we spawn all
    // tasks immediately below.
    //
    // `Arc` = Atomic Reference Counted pointer. We need it
    // because the Semaphore is shared across many async tasks,
    // and Rust's borrow checker needs to know it will live long
    // enough. `Arc::clone` is cheap — it just increments a counter.
    // --------------------------------------------------------
    let semaphore = Arc::new(Semaphore::new(args.concurrency));

    // Convert timeout from milliseconds to a Duration type,
    // which is what tokio's timeout() function expects.
    let timeout = std::time::Duration::from_millis(args.timeout_ms);

    // --------------------------------------------------------
    // Step 5: Spawn one async task per (host, port) pair.
    //
    // `tokio::spawn` sends a task to the tokio thread pool.
    // It returns a JoinHandle — a future that resolves to the
    // task's return value when it completes.
    //
    // We collect all handles into a Vec so we can await them
    // all after spawning.
    // --------------------------------------------------------
    let mut handles = Vec::new();

    for host in &targets {
        for &port in &ports {
            // Clone values that need to be moved into the async task.
            // Rust closures capture by move when spawning tasks,
            // so we clone the parts the task needs to own.
            let host = host.clone();
            let sem = Arc::clone(&semaphore);  // Cheap — just increments refcount
            let pb = pb.clone();               // ProgressBar is internally Arc'd
            let do_banner = grab_banner;

            let handle = tokio::spawn(async move {
                // Acquire a permit — this will WAIT (yield, not block a thread)
                // if the semaphore is full. The permit drops at end of this block.
                let _permit = sem.acquire().await.unwrap();

                // Do the actual TCP probe (defined in scanner.rs)
                let result = scanner::scan_port(&host, port, timeout, do_banner).await;

                // Advance the progress bar by one tick
                pb.inc(1);

                result  // Return the ScanResult from this task
            });

            handles.push(handle);
        }
    }

    // --------------------------------------------------------
    // Step 6: Collect results.
    //
    // We await each JoinHandle in order. The tasks themselves
    // ran concurrently while we were spawning — we're just
    // gathering the outputs now.
    //
    // `handle.await` returns Result<ScanResult, JoinError>.
    // We unwrap the outer Result (task panic) and keep the inner.
    // --------------------------------------------------------
    let mut results: Vec<ScanResult> = Vec::new();

    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    // Clear the progress bar before printing results
    pb.finish_and_clear();

    // --------------------------------------------------------
    // Step 7: Sort results for readable output.
    //
    // Primary key: open ports first (true > false in Rust bool ord)
    // Secondary: host string alphabetically
    // Tertiary: port number ascending
    // --------------------------------------------------------
    results.sort_by(|a, b| {
        b.is_open
            .cmp(&a.is_open)
            .then(a.host.cmp(&b.host))
            .then(a.port.cmp(&b.port))
    });

    // --------------------------------------------------------
    // Step 8: Print output — either JSON or a human table.
    // --------------------------------------------------------
    if args.json {
        output::print_json(&results);
    } else {
        output::print_table(&results, args.open_only);
    }

    // --------------------------------------------------------
    // Step 9: Run the analyst engine if --analyze was set.
    //
    // We group results by host, then call analyst::analyze()
    // for each host and render a report.
    //
    // For a single-host scan this is trivial. For a CIDR scan
    // we produce one report per host that had open ports.
    // --------------------------------------------------------
    if args.analyze {
        // Collect all unique hosts that had at least one open port.
        // We use a Vec instead of a HashSet to preserve scan order.
        let mut seen_hosts: Vec<String> = Vec::new();
        for r in &results {
            if r.is_open && !seen_hosts.contains(&r.host) {
                seen_hosts.push(r.host.clone());
            }
        }

        if seen_hosts.is_empty() {
            println!("\n{} No open ports found — nothing to analyze.", "🐽".bold());
        } else {
            for host in &seen_hosts {
                // Collect all results for this specific host
                let host_results: Vec<ScanResult> = results
                    .iter()
                    .filter(|r| &r.host == host)
                    .cloned()
                    .collect();

                // Run the analysis and render the report
                let report = analyst::analyze(host, &host_results);
                analyst::render_report(&report);
            }
        }
    }

    // Final summary line
    let open_count = results.iter().filter(|r| r.is_open).count();
    println!(
        "\n{} scan complete · {} open port(s) found",
        "✓".green().bold(),
        open_count.to_string().green().bold(),
    );
}


// ============================================================
// parse_ports
//
// Converts a port string like "22,80,1000-2000" into a
// sorted, deduplicated Vec<u16>.
//
// Accepts three formats (mixable with commas):
//   Single port:   "80"
//   Range:         "1000-2000"
//   Comma list:    "22,80,443"
//   Combined:      "22,80,1000-2000,8080"
//
// Returns Err(String) with a human message on bad input.
// ============================================================
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    // Split on commas first to get individual tokens
    for part in input.split(',') {
        let part = part.trim();

        if part.contains('-') {
            // Token looks like "1000-2000" — split on the dash
            let sides: Vec<&str> = part.splitn(2, '-').collect();
            if sides.len() != 2 {
                return Err(format!("invalid range: {part}"));
            }

            // Parse both ends as u16 (0–65535 is the valid port range)
            let start: u16 = sides[0]
                .parse()
                .map_err(|_| format!("invalid port: {}", sides[0]))?;
            let end: u16 = sides[1]
                .parse()
                .map_err(|_| format!("invalid port: {}", sides[1]))?;

            if start > end {
                return Err(format!("range start > end: {part}"));
            }

            // Push every port in the range into our list (inclusive on both ends)
            for p in start..=end {
                ports.push(p);
            }
        } else {
            // Token is a single port number — parse directly
            let p: u16 = part.parse().map_err(|_| format!("invalid port: {part}"))?;
            ports.push(p);
        }
    }

    // Sort and remove any duplicates (e.g. "80,80" or overlapping ranges)
    ports.sort_unstable();
    ports.dedup();

    Ok(ports)
}


// ============================================================
// print_logo
//
// Just cosmetic — prints the SniffSnorf name on startup.
// Using `colored` crate's `.cyan()` and `.bold()` methods.
// ============================================================
fn print_logo() {
    println!(
        "{}",
        r#"
  ███████╗███╗   ██╗██╗███████╗███████╗███████╗███╗   ██╗ ██████╗ ██████╗ ███████╗
  ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝████╗  ██║██╔═══██╗██╔══██╗██╔════╝
  ███████╗██╔██╗ ██║██║█████╗  █████╗  ███████╗██╔██╗ ██║██║   ██║██████╔╝█████╗
  ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ╚════██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝
  ███████║██║ ╚████║██║██║     ██║     ███████║██║ ╚████║╚██████╔╝██║  ██║██║
  ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  🐽"#
            .cyan()
    );
    println!(
        "  {}\n",
        "async port scanner · tokio-powered".truecolor(120, 120, 120)
    );
}
