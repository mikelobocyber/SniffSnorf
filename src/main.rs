// ============================================================
// main.rs — SniffSnorf entry point
// ============================================================

mod analyst;
mod banner;
mod cidr;
mod output;
mod scanner;

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::scanner::ScanResult;

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
    #[arg(short, long, default_value = "1-1024")]
    pub ports: String,

    /// Maximum number of simultaneous TCP connections
    #[arg(short, long, default_value = "500")]
    pub concurrency: usize,

    /// Connect timeout per port in milliseconds
    #[arg(short, long, default_value = "1000")]
    pub timeout_ms: u64,

    /// Grab service banners from open ports
    #[arg(short, long)]
    pub banner: bool,

    /// Output results as newline-delimited JSON
    #[arg(short, long)]
    pub json: bool,

    /// Only print open ports
    #[arg(short = 'q', long)]
    pub open_only: bool,

    /// Run the analyst engine (implies --banner)
    #[arg(short = 'a', long)]
    pub analyze: bool,

    /// Save output to a file. Extension sets format:
    ///   scan.html  — styled HTML report
    ///   scan.txt   — plain text (no color codes)
    ///   scan.json  — JSON findings
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<String>,

    /// Open the output file automatically after writing (requires -o)
    #[arg(long)]
    pub open: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Html,
    Json,
    Text,
}

fn detect_format(path: &str) -> OutputFormat {
    let lower = path.to_lowercase();
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        OutputFormat::Html
    } else if lower.ends_with(".json") {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    }
}

fn open_file(path: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
        return;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn();
        return;
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        match std::process::Command::new("xdg-open").arg(path).spawn() {
            Ok(_) => {}
            Err(e) => eprintln!(
                "{} could not open file automatically: {}",
                "warning:".yellow().bold(),
                e
            ),
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    print_logo();

    let targets = match crate::cidr::resolve_targets(&args.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    let total = targets.len() as u64 * ports.len() as u64;

    println!(
        "{} {} host(s) · {} port(s) · {} total probes · concurrency {}\n",
        "🐽".bold(),
        targets.len().to_string().white().bold(),
        ports.len().to_string().white().bold(),
        total.to_string().white().bold(),
        args.concurrency.to_string().yellow(),
    );

    let grab_banner = args.banner || args.analyze;

    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("█▓░"),
    );

    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let timeout = std::time::Duration::from_millis(args.timeout_ms);
    let mut handles = Vec::new();

    for host in &targets {
        for &port in &ports {
            let host = host.clone();
            let sem = Arc::clone(&semaphore);
            let pb = pb.clone();
            let do_banner = grab_banner;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let result = scanner::scan_port(&host, port, timeout, do_banner).await;
                pb.inc(1);
                result
            });

            handles.push(handle);
        }
    }

    let mut results: Vec<ScanResult> = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    pb.finish_and_clear();

    results.sort_by(|a, b| {
        b.is_open
            .cmp(&a.is_open)
            .then(a.host.cmp(&b.host))
            .then(a.port.cmp(&b.port))
    });

    // Print scan table to terminal
    if args.json {
        output::print_json(&results);
    } else {
        output::print_table(&results, args.open_only);
    }

    // Run analyst engine, collect reports
    let mut reports: Vec<analyst::HostReport> = Vec::new();

    if args.analyze {
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
                let host_results: Vec<ScanResult> = results
                    .iter()
                    .filter(|r| &r.host == host)
                    .cloned()
                    .collect();

                let report = analyst::analyze(host, &host_results);
                analyst::render_report(&report);
                reports.push(report);
            }
        }
    }

    let open_count = results.iter().filter(|r| r.is_open).count();
    println!(
        "\n{} scan complete · {} open port(s) found",
        "✓".green().bold(),
        open_count.to_string().green().bold(),
    );

    // Write output file if -o was given
    if let Some(ref path) = args.output {
        let format = detect_format(path);

        let write_result = match format {
            OutputFormat::Html => {
                let html = output::render_html(&results, &reports, &args.target);
                std::fs::write(path, html)
            }
            OutputFormat::Json => {
                let json = output::render_json_string(&results);
                std::fs::write(path, json)
            }
            OutputFormat::Text => {
                let mut text = output::render_table_plain(&results, args.open_only);
                for r in &reports {
                    text.push('\n');
                    text.push_str(&analyst::render_report_plain(r));
                }
                std::fs::write(path, text)
            }
        };

        match write_result {
            Ok(_) => {
                println!(
                    "{} saved → {}",
                    "✓".green().bold(),
                    path.white().bold()
                );
                if args.open {
                    open_file(path);
                }
            }
            Err(e) => {
                eprintln!("{} could not write {}: {}", "error:".red().bold(), path, e);
            }
        }
    } else if args.open {
        eprintln!(
            "{} --open has no effect without -o",
            "warning:".yellow().bold()
        );
    }
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in input.split(',') {
        let part = part.trim();

        if part.contains('-') {
            let sides: Vec<&str> = part.splitn(2, '-').collect();
            if sides.len() != 2 {
                return Err(format!("invalid range: {part}"));
            }

            let start: u16 = sides[0]
                .parse()
                .map_err(|_| format!("invalid port: {}", sides[0]))?;
            let end: u16 = sides[1]
                .parse()
                .map_err(|_| format!("invalid port: {}", sides[1]))?;

            if start > end {
                return Err(format!("range start > end: {part}"));
            }

            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("invalid port: {part}"))?;
            ports.push(p);
        }
    }

    ports.sort_unstable();
    ports.dedup();

    Ok(ports)
}

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
