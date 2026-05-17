// ============================================================
// output.rs — Result rendering
//
// Public functions:
//   print_table(results, open_only)       — colored terminal table
//   print_json(results)                   — NDJSON to stdout
//   render_table_plain(results, open_only) -> String  — plain text, no ANSI
//   render_json_string(results)            -> String  — JSON string for file
//   render_html(results, reports, target)  -> String  — full HTML report
// ============================================================

use colored::*;
use crate::scanner::ScanResult;
use crate::analyst::{HostReport, Severity};


// ============================================================
// Terminal output (existing behavior, unchanged)
// ============================================================

pub fn print_table(results: &[ScanResult], open_only: bool) {
    let to_show: Vec<&ScanResult> = results
        .iter()
        .filter(|r| !open_only || r.is_open)
        .collect();

    if to_show.is_empty() {
        println!("{}", "  no open ports found".truecolor(120, 120, 120));
        return;
    }

    println!(
        "  {:<20} {:<7} {:<18} {:<10} {}",
        "HOST".truecolor(160, 160, 160),
        "PORT".truecolor(160, 160, 160),
        "SERVICE".truecolor(160, 160, 160),
        "STATE".truecolor(160, 160, 160),
        "BANNER".truecolor(160, 160, 160),
    );

    println!("  {}", "─".repeat(80).truecolor(60, 60, 60));

    for r in to_show {
        let state = if r.is_open {
            "open".green().bold()
        } else {
            "closed".truecolor(80, 80, 80).into()
        };

        let service = r
            .service
            .map(|s| s.cyan().to_string())
            .unwrap_or_else(|| "-".truecolor(80, 80, 80).to_string());

        let banner = r
            .banner
            .as_deref()
            .map(|b| b.truecolor(200, 200, 140).to_string())
            .unwrap_or_default();

        if r.is_open {
            println!(
                "  {:<20} {:<7} {:<28} {:<20} {}",
                r.host.white(),
                r.port.to_string().yellow().bold(),
                service,
                state,
                banner,
            );
        } else {
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

pub fn print_json(results: &[ScanResult]) {
    for r in results {
        let line = format_json_line(r);
        println!("{line}");
    }
}


// ============================================================
// Plain text rendering (for .txt file output)
// ============================================================

pub fn render_table_plain(results: &[ScanResult], open_only: bool) -> String {
    let to_show: Vec<&ScanResult> = results
        .iter()
        .filter(|r| !open_only || r.is_open)
        .collect();

    let mut out = String::new();

    if to_show.is_empty() {
        out.push_str("  no open ports found\n");
        return out;
    }

    out.push_str(&format!(
        "  {:<20} {:<7} {:<18} {:<10} {}\n",
        "HOST", "PORT", "SERVICE", "STATE", "BANNER"
    ));
    out.push_str(&format!("  {}\n", "─".repeat(80)));

    for r in to_show {
        let state = if r.is_open { "open" } else { "closed" };
        let service = r.service.unwrap_or("-");
        let banner = r.banner.as_deref().unwrap_or("");

        if r.is_open {
            out.push_str(&format!(
                "  {:<20} {:<7} {:<18} {:<10} {}\n",
                r.host, r.port, service, state, banner
            ));
        } else {
            out.push_str(&format!(
                "  {:<20} {:<7} {:<18} {}\n",
                r.host, r.port, "-", state
            ));
        }
    }

    out
}


// ============================================================
// JSON string rendering (for .json file output)
// ============================================================

pub fn render_json_string(results: &[ScanResult]) -> String {
    results
        .iter()
        .map(|r| format_json_line(r))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn format_json_line(r: &ScanResult) -> String {
    let service = r
        .service
        .map(|s| format!("\"{}\"", s))
        .unwrap_or_else(|| "null".to_string());

    let banner = r
        .banner
        .as_deref()
        .map(|b| format!("\"{}\"", b.replace('"', "\\\"")))
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"host\":\"{}\",\"port\":{},\"open\":{},\"service\":{},\"banner\":{},\"latency_ms\":{}}}",
        r.host, r.port, r.is_open, service, banner, r.latency_ms,
    )
}


// ============================================================
// HTML rendering (for .html file output)
//
// Self-contained single file. No external dependencies.
// Dark theme, severity color coding, clickable MITRE links.
// ============================================================

pub fn render_html(results: &[ScanResult], reports: &[HostReport], target: &str) -> String {
    let scan_time = chrono_now();
    let open_count = results.iter().filter(|r| r.is_open).count();

    // Build the port table rows
    let port_rows: String = results
        .iter()
        .filter(|r| r.is_open)
        .map(|r| {
            let service = r.service.unwrap_or("-");
            let banner = r.banner.as_deref().unwrap_or("-");
            format!(
                "<tr><td>{}</td><td class=\"port\">{}</td><td class=\"svc\">{}</td><td>{}</td></tr>",
                html_escape(&r.host),
                r.port,
                html_escape(service),
                html_escape(banner),
            )
        })
        .collect();

    // Build analyst report sections
    let report_sections: String = reports.iter().map(render_report_html).collect();

    // Whether we have any analyst content
    let analyst_section = if reports.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"analyst\"><h2>&#x1F43A; Analyst Report</h2>{report_sections}</section>"
        )
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SniffSnorf &mdash; {target}</title>
<style>
  :root {{
    --bg:       #0f1117;
    --bg2:      #1a1d27;
    --bg3:      #22263a;
    --border:   #2e3250;
    --text:     #d4d8f0;
    --muted:    #6b7099;
    --accent:   #5bc4f5;
    --green:    #4caf80;
    --yellow:   #f5c842;
    --crit:     #e53935;
    --high:     #f57c00;
    --med:      #f9a825;
    --low:      #42a5f5;
    --info:     #78909c;
    --mitre:    #b39ddb;
    --port:     #f5c842;
    --svc:      #5bc4f5;
    --radius:   6px;
    --mono:     'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
    max-width: 960px;
    margin: 0 auto;
  }}

  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}

  .logo {{
    font-family: var(--mono);
    color: var(--accent);
    font-size: 1.4rem;
    font-weight: 700;
    letter-spacing: 0.05em;
  }}

  .meta {{
    color: var(--muted);
    font-size: 0.85rem;
    margin-top: 0.4rem;
  }}

  .meta span {{ color: var(--text); }}

  .stats {{
    display: flex;
    gap: 2rem;
    margin: 1.5rem 0;
    flex-wrap: wrap;
  }}

  .stat {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.8rem 1.2rem;
    min-width: 120px;
  }}

  .stat-label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .stat-value {{ color: var(--accent); font-size: 1.6rem; font-weight: 700; font-family: var(--mono); }}

  section {{ margin-bottom: 2.5rem; }}

  h2 {{
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.8rem;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--bg2);
    border-radius: var(--radius);
    overflow: hidden;
    border: 1px solid var(--border);
  }}

  th {{
    background: var(--bg3);
    color: var(--muted);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.6rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}

  td {{
    padding: 0.55rem 0.8rem;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.82rem;
    vertical-align: top;
  }}

  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg3); }}

  td.port {{ color: var(--port); font-weight: 600; }}
  td.svc  {{ color: var(--svc); }}

  .host-report {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}

  .host-header {{
    background: var(--bg3);
    padding: 0.8rem 1.2rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }}

  .host-ip {{
    font-family: var(--mono);
    font-size: 1rem;
    font-weight: 700;
    color: var(--accent);
  }}

  .host-type {{
    color: var(--muted);
    font-size: 0.8rem;
  }}

  .port-count {{
    margin-left: auto;
    color: var(--yellow);
    font-family: var(--mono);
    font-size: 0.8rem;
  }}

  .summary {{
    padding: 1rem 1.2rem;
    color: var(--text);
    border-bottom: 1px solid var(--border);
    line-height: 1.7;
  }}

  .findings {{ padding: 0.8rem 1.2rem; }}

  .finding {{
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 0.8rem;
    overflow: hidden;
  }}

  .finding:last-child {{ margin-bottom: 0; }}

  .finding-header {{
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.6rem 0.8rem;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }}

  .badge {{
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    text-transform: uppercase;
    flex-shrink: 0;
  }}

  .badge-CRITICAL {{ background: var(--crit);  color: #fff; }}
  .badge-HIGH     {{ background: var(--high);  color: #fff; }}
  .badge-MEDIUM   {{ background: var(--med);   color: #111; }}
  .badge-LOW      {{ background: var(--low);   color: #fff; }}
  .badge-INFO     {{ background: var(--info);  color: #fff; }}

  .finding-title {{ font-weight: 600; color: var(--text); }}

  .finding-body {{
    padding: 0.7rem 0.8rem;
    display: grid;
    grid-template-columns: 80px 1fr;
    gap: 0.3rem 0.8rem;
    font-size: 0.82rem;
  }}

  .finding-label {{ color: var(--muted); }}

  .finding-ports {{ color: var(--yellow); font-family: var(--mono); }}

  .finding-mitre a {{
    color: var(--mitre);
    text-decoration: none;
    font-family: var(--mono);
  }}
  .finding-mitre a:hover {{ text-decoration: underline; }}

  .finding-detail {{
    grid-column: 1 / -1;
    color: var(--text);
    line-height: 1.65;
    padding-top: 0.2rem;
  }}

  .severity-bar {{
    display: flex;
    gap: 1rem;
    padding: 0.7rem 1.2rem;
    border-top: 1px solid var(--border);
    font-size: 0.78rem;
    flex-wrap: wrap;
  }}

  .sev-item {{ display: flex; align-items: center; gap: 0.4rem; }}
  .sev-dot  {{ width: 8px; height: 8px; border-radius: 50%; }}

  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.75rem;
    text-align: center;
  }}
</style>
</head>
<body>

<header>
  <div class="logo">&#x1F43D; SniffSnorf</div>
  <div class="meta">
    Target: <span>{target}</span> &nbsp;&middot;&nbsp;
    Scanned: <span>{scan_time}</span> &nbsp;&middot;&nbsp;
    Open ports: <span>{open_count}</span>
  </div>
</header>

<div class="stats">
  <div class="stat">
    <div class="stat-label">Open Ports</div>
    <div class="stat-value">{open_count}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Hosts Analyzed</div>
    <div class="stat-value">{host_count}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Findings</div>
    <div class="stat-value">{finding_count}</div>
  </div>
</div>

<section>
  <h2>Open Ports</h2>
  <table>
    <thead>
      <tr>
        <th>Host</th>
        <th>Port</th>
        <th>Service</th>
        <th>Banner</th>
      </tr>
    </thead>
    <tbody>
      {port_rows}
    </tbody>
  </table>
</section>

{analyst_section}

<footer>
  Generated by <strong>SniffSnorf</strong> &mdash; Only scan networks you own or have written permission to test.
</footer>

</body>
</html>
"#,
        target = html_escape(target),
        scan_time = scan_time,
        open_count = open_count,
        host_count = reports.len(),
        finding_count = reports.iter().map(|r| r.findings.len()).sum::<usize>(),
        port_rows = port_rows,
        analyst_section = analyst_section,
    )
}

fn render_report_html(report: &HostReport) -> String {
    let port_list: Vec<String> = report.open_ports.iter().map(|p| p.to_string()).collect();

    let findings_html: String = report.findings.iter().enumerate().map(|(i, f)| {
        let badge_class = format!("badge-{}", f.severity.label());
        let ports_str = f.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");

        let mitre_html = f.mitre.map(|m| format!(
            r#"<div class="finding-label">MITRE</div>
               <div class="finding-mitre"><a href="https://attack.mitre.org/techniques/{link}" target="_blank" rel="noopener">{m}</a></div>"#,
            link = m.replace('.', "/"),
            m = m,
        )).unwrap_or_default();

        format!(
            r#"<div class="finding">
  <div class="finding-header">
    <span class="badge {badge_class}">{sev}</span>
    <span class="finding-title">[{num}] {title}</span>
  </div>
  <div class="finding-body">
    <div class="finding-label">Ports</div>
    <div class="finding-ports">{ports}</div>
    {mitre}
    <div class="finding-detail">{detail}</div>
  </div>
</div>"#,
            badge_class = badge_class,
            sev = f.severity.label(),
            num = i + 1,
            title = html_escape(&f.title),
            ports = html_escape(&ports_str),
            mitre = mitre_html,
            detail = html_escape(&f.detail),
        )
    }).collect();

    // Severity summary bar
    let sev_counts = [
        (Severity::Critical, "CRITICAL", "#e53935"),
        (Severity::High,     "HIGH",     "#f57c00"),
        (Severity::Medium,   "MEDIUM",   "#f9a825"),
        (Severity::Low,      "LOW",      "#42a5f5"),
        (Severity::Info,     "INFO",     "#78909c"),
    ];

    let sev_bar: String = sev_counts.iter().filter_map(|(sev, label, color)| {
        let n = report.findings.iter().filter(|f| &f.severity == sev).count();
        if n > 0 {
            Some(format!(
                r#"<div class="sev-item"><div class="sev-dot" style="background:{color}"></div>{n} {label}</div>"#,
                color = color, n = n, label = label
            ))
        } else {
            None
        }
    }).collect();

    let findings_section = if report.findings.is_empty() {
        "<p style=\"color:var(--green);padding:1rem 1.2rem\">&#x2713; No notable findings.</p>".to_string()
    } else {
        format!("<div class=\"findings\">{findings_html}</div>")
    };

    format!(
        r#"<div class="host-report">
  <div class="host-header">
    <span class="host-ip">{host}</span>
    <span class="host-type">{htype}</span>
    <span class="port-count">{pcount} open port{ps}</span>
  </div>
  <div class="summary">{summary}</div>
  {findings_section}
  {sev_bar_section}
</div>"#,
        host = html_escape(&report.host),
        htype = report.host_type.description(),
        pcount = report.open_ports.len(),
        ps = if report.open_ports.len() == 1 { "" } else { "s" },
        summary = html_escape(&report.summary),
        findings_section = findings_section,
        sev_bar_section = if sev_bar.is_empty() {
            String::new()
        } else {
            format!("<div class=\"severity-bar\">{sev_bar}</div>")
        },
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}

// Returns a simple UTC timestamp string without pulling in chrono.
// Format: 2026-05-16 14:32:07 UTC
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Rough Gregorian calendar calculation
    let mut year = 1970u32;
    let mut remaining = days;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if remaining < days_in_year { break; }
        remaining -= days_in_year;
        year += 1;
    }

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u32;
    for &dim in &days_in_month {
        if remaining < dim { break; }
        remaining -= dim;
        month += 1;
    }
    let day = remaining + 1;

    format!("{year}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}
