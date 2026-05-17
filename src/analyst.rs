// ============================================================
// analyst.rs — Threat surface narration engine
//
// This is the module that makes SniffSnorf different from every
// other port scanner. Instead of just dumping a table of open
// ports, it reads the results the way a human analyst would:
//
//   - What KIND of host is this? (web server, database box, router...)
//   - What's normal about this exposure? What's weird?
//   - What should someone actually be worried about here?
//
// The output is plain-English narrative + severity-tagged findings,
// not a raw port list.
//
// MITRE ATT&CK mappings are included on findings so this output
// can be dropped directly into a pentest report or a Wazuh rule
// description.
//
// How it works:
//   1. `fingerprint_host()` looks at the SET of open ports and
//      decides what kind of host this probably is.
//   2. `analyze()` runs all the finding detectors against the
//      results and collects Finding structs.
//   3. `render_report()` formats everything into colored terminal
//      output with severity badges and narrative prose.
// ============================================================

use colored::*;
use crate::scanner::ScanResult;


// ============================================================
// Severity
//
// Each finding gets a severity level. These mirror the CVSS
// qualitative scale (Critical/High/Medium/Low/Info) so the
// output maps naturally to pentest report templates.
// ============================================================
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    // Returns a colored badge string for terminal output.
    // We use fixed-width labels so findings line up in columns.
    pub fn badge(&self) -> colored::ColoredString {
        match self {
            Severity::Critical => " CRIT ".on_red().white().bold(),
            Severity::High     => " HIGH ".on_truecolor(200, 80, 0).white().bold(),
            Severity::Medium   => " MED  ".on_yellow().truecolor(40, 20, 0).bold(),
            Severity::Low      => " LOW  ".on_blue().white(),
            Severity::Info     => " INFO ".on_truecolor(60, 60, 60).white(),
        }
    }

    // A short label for use in non-colored contexts (e.g. JSON export)
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }
}


// ============================================================
// HostType
//
// Our best guess at what kind of machine this is, based on
// which ports are open in combination.
//
// This is heuristic — it will be wrong sometimes. The narrative
// output says "this looks like" rather than "this is" for that reason.
// ============================================================
#[derive(Debug, Clone, PartialEq)]
pub enum HostType {
    WebServer,         // HTTP/HTTPS open, maybe also SSH
    DatabaseServer,    // One or more DB ports open, no web
    MailServer,        // SMTP/IMAP/POP3 combination
    WindowsHost,       // SMB, RDP, MSRPC present
    NetworkDevice,     // SNMP, telnet, no typical server ports
    LinuxServer,       // SSH open, mixed services
    ContainerHost,     // Docker API or k8s API exposed
    DevelopmentBox,    // Dev ports: 3000, 8080, 8888, jupyter
    Unknown,           // Not enough signal to guess
}

impl HostType {
    // Human-readable description used in the narrative header
    pub fn description(&self) -> &'static str {
        match self {
            HostType::WebServer      => "web server",
            HostType::DatabaseServer => "database server",
            HostType::MailServer     => "mail server",
            HostType::WindowsHost    => "Windows host",
            HostType::NetworkDevice  => "network device (router/switch/appliance)",
            HostType::LinuxServer    => "Linux server",
            HostType::ContainerHost  => "container host / orchestration node",
            HostType::DevelopmentBox => "development machine",
            HostType::Unknown        => "host (type unclear)",
        }
    }
}


// ============================================================
// Finding
//
// One discrete security observation. Each finding has:
//   - A severity level
//   - A short title (one line)
//   - A plain-English explanation of why this matters
//   - An optional MITRE ATT&CK technique ID
//   - The port(s) that triggered this finding
// ============================================================
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity:    Severity,
    pub title:       String,
    pub detail:      String,
    pub mitre:       Option<&'static str>,  // e.g. "T1021.002"
    pub ports:       Vec<u16>,
}


// ============================================================
// HostReport
//
// The complete analysis output for one host.
// Produced by `analyze()`, consumed by `render_report()`.
// ============================================================
#[derive(Debug)]
pub struct HostReport {
    pub host:      String,
    pub host_type: HostType,
    pub summary:   String,       // One-paragraph narrative description
    pub findings:  Vec<Finding>, // Sorted by severity (Critical first)
    pub open_ports: Vec<u16>,    // Just the open port numbers, for convenience
}


// ============================================================
// analyze  (public — called from main.rs)
//
// Takes the full list of ScanResults for ONE host and produces
// a HostReport with fingerprint, narrative, and findings.
//
// Caller is responsible for grouping results by host first if
// scanning a CIDR range (see main.rs).
// ============================================================
pub fn analyze(host: &str, results: &[ScanResult]) -> HostReport {

    // Collect just the open ports — we'll reference this list a lot
    let open_ports: Vec<u16> = results
        .iter()
        .filter(|r| r.is_open)
        .map(|r| r.port)
        .collect();

    // Helper closure: check if a specific port is in the open list.
    // Closures in Rust can capture variables from their enclosing scope.
    let is_open = |p: u16| open_ports.contains(&p);

    // Helper closure: check if ANY port from a list is open.
    // Used for "any of these database ports" style checks.
    let any_open = |ports: &[u16]| ports.iter().any(|&p| open_ports.contains(&p));

    // --------------------------------------------------------
    // Step 1: Fingerprint the host type
    // --------------------------------------------------------
    let host_type = fingerprint_host(&open_ports);

    // --------------------------------------------------------
    // Step 2: Run all finding detectors
    //
    // Each `check_*` function below looks for a specific pattern
    // and returns Option<Finding> — Some if it found something,
    // None if not. We collect all the Somes into our findings list.
    // --------------------------------------------------------
    let mut findings: Vec<Finding> = Vec::new();

    // Macro to reduce boilerplate: push a finding if the check returns Some.
    // This is equivalent to `if let Some(f) = check_x() { findings.push(f) }`
    macro_rules! check {
        ($fn:expr) => {
            if let Some(f) = $fn {
                findings.push(f);
            }
        };
    }

    // --- Critical / High severity checks ---
    check!(check_telnet(is_open));
    check!(check_docker_exposed(is_open));
    check!(check_metasploit_port(is_open));
    check!(check_rdp_exposed(is_open));
    check!(check_smb_exposed(is_open));

    // --- Database exposure checks ---
    check!(check_database_exposed("MySQL",         3306, is_open));
    check!(check_database_exposed("PostgreSQL",    5432, is_open));
    check!(check_database_exposed("MongoDB",      27017, is_open));
    check!(check_database_exposed("Redis",         6379, is_open));
    check!(check_database_exposed("MSSQL",         1433, is_open));
    check!(check_database_exposed("Elasticsearch", 9200, is_open));

    // --- Medium severity checks ---
    check!(check_ftp(is_open));
    check!(check_snmp(is_open));
    check!(check_vnc(is_open));
    check!(check_ldap_unencrypted(is_open));
    check!(check_kubernetes_api(is_open));

    // --- Low / Info checks ---
    check!(check_ssh_present(is_open));
    check!(check_http_without_https(is_open));
    check!(check_dev_ports_exposed(any_open));
    check!(check_mail_server(any_open));
    check!(check_jupyter(is_open));

    // --------------------------------------------------------
    // Step 3: Banner-based checks
    //
    // These look at the actual banner text, not just the port.
    // Banner analysis can catch version-specific issues.
    // --------------------------------------------------------
    for result in results.iter().filter(|r| r.is_open) {
        if let Some(banner) = &result.banner {
            if let Some(f) = check_banner_issues(result.port, banner) {
                findings.push(f);
            }
        }
    }

    // --------------------------------------------------------
    // Step 4: Sort findings by severity (Critical → Info)
    //
    // Our Severity enum derives Ord, and we ordered the variants
    // Critical → Info, so sorting ascending puts Critical first.
    // --------------------------------------------------------
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    // --------------------------------------------------------
    // Step 5: Write the narrative summary paragraph
    // --------------------------------------------------------
    let summary = build_summary(host, &host_type, &open_ports, &findings);

    HostReport {
        host: host.to_string(),
        host_type,
        summary,
        findings,
        open_ports,
    }
}


// ============================================================
// fingerprint_host
//
// Looks at the set of open ports and makes a best-guess about
// what kind of machine this is.
//
// The order of checks matters — more specific patterns first.
// "ContainerHost" requires Docker API, so it's checked before
// generic "LinuxServer" (which just needs SSH).
// ============================================================
fn fingerprint_host(open: &[u16]) -> HostType {
    let has = |p: u16| open.contains(&p);
    let any = |ports: &[u16]| ports.iter().any(|&p| open.contains(&p));

    // Docker / Kubernetes — very specific ports, check first
    if any(&[2375, 2376, 6443]) {
        return HostType::ContainerHost;
    }

    // Windows fingerprint: SMB + RDP + MSRPC together is very distinctive
    if any(&[445, 139]) && any(&[135, 3389]) {
        return HostType::WindowsHost;
    }

    // Mail server: needs at least two of the mail protocol ports
    let mail_ports = [25, 110, 143, 465, 587, 993, 995];
    let mail_count = mail_ports.iter().filter(|&&p| has(p)).count();
    if mail_count >= 2 {
        return HostType::MailServer;
    }

    // Development box: dev-specific ports with no production indicators
    let dev_ports = [3000, 8080, 8888, 4200, 5000, 9000];
    if any(&dev_ports) && !has(443) && !any(&[3306, 5432, 27017]) {
        return HostType::DevelopmentBox;
    }

    // Web server: HTTP or HTTPS, with or without SSH
    if any(&[80, 443, 8080, 8443]) {
        return HostType::WebServer;
    }

    // Database server: DB ports without web ports
    let db_ports = [3306, 5432, 1433, 27017, 6379, 9200, 1521];
    if any(&db_ports) && !any(&[80, 443]) {
        return HostType::DatabaseServer;
    }

    // Network device: SNMP is a strong signal, often with telnet
    if has(161) || (has(23) && !has(22)) {
        return HostType::NetworkDevice;
    }

    // Linux server: SSH is the baseline, mixed other services
    if has(22) {
        return HostType::LinuxServer;
    }

    HostType::Unknown
}


// ============================================================
// build_summary
//
// Writes the one-paragraph narrative that appears at the top
// of the report. It's opinionated plain English — not a list,
// not bullet points, just what a human analyst would say first.
// ============================================================
fn build_summary(
    host: &str,
    host_type: &HostType,
    open_ports: &[u16],
    findings: &[Finding],
) -> String {
    let port_count = open_ports.len();

    // Count findings by severity for the summary tone
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

    // Opening sentence: what we found and what it looks like
    let opener = if port_count == 0 {
        format!("{host} returned no open ports in the scanned range. The host may be offline, firewalled, or using non-standard ports.")
    } else {
        format!(
            "{host} has {} open port{} and appears to be a {}.",
            port_count,
            if port_count == 1 { "" } else { "s" },
            host_type.description()
        )
    };

    // Middle: severity summary
    let risk_summary = if critical > 0 {
        format!(
            " The surface includes {} critical finding{} that warrant immediate attention.",
            critical,
            if critical == 1 { "" } else { "s" }
        )
    } else if high > 0 {
        format!(
            " {} high-severity finding{} present elevated risk.",
            high,
            if high == 1 { "" } else { "s" }
        )
    } else if medium > 0 {
        format!(
            " {} medium-severity finding{} should be reviewed.",
            medium,
            if medium == 1 { "" } else { "s" }
        )
    } else if port_count > 0 {
        " No high-severity issues detected in the open ports. Review the findings below for context.".to_string()
    } else {
        String::new()
    };

    // Closing: host-type-specific context
    let context = match host_type {
        HostType::WindowsHost =>
            " SMB and RPC exposure on a Windows host is a common lateral movement path — verify this host is not reachable from untrusted networks.",
        HostType::DatabaseServer =>
            " Database ports reachable from the network without an application-layer proxy are a significant data exposure risk.",
        HostType::ContainerHost =>
            " An exposed container API (Docker or Kubernetes) can allow an attacker to deploy arbitrary workloads and escape to the host.",
        HostType::DevelopmentBox =>
            " Development services are often run without authentication or TLS. Confirm this host is not reachable from production or external networks.",
        HostType::MailServer =>
            " Mail servers require careful TLS and relay configuration. Open relays and unencrypted submission ports are common misconfigurations.",
        _ => "",
    };

    format!("{opener}{risk_summary}{context}")
}


// ============================================================
// Individual finding detectors
//
// Each function checks for ONE specific condition and returns
// Option<Finding>. None means "nothing to report here."
//
// The `impl Fn(u16) -> bool` argument type means: accept any
// function/closure that takes a u16 and returns a bool. This
// lets us pass the `is_open` closure from `analyze()` without
// coupling these functions to the full results list.
// ============================================================

fn check_telnet(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(23) { return None; }
    Some(Finding {
        severity: Severity::Critical,
        title:    "Telnet is open (port 23)".to_string(),
        detail:   "Telnet transmits all data including credentials in plaintext. \
                   Any attacker with network access can passively capture usernames \
                   and passwords. Replace with SSH immediately. There is no safe \
                   configuration for Telnet on a network-accessible host.".to_string(),
        mitre:    Some("T1021.004"),  // Remote Services: SSH (Telnet is the insecure predecessor)
        ports:    vec![23],
    })
}

fn check_docker_exposed(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    // Port 2375 = Docker API without TLS (plaintext, critical)
    // Port 2376 = Docker API with TLS (still risky if exposed publicly)
    if is_open(2375) {
        return Some(Finding {
            severity: Severity::Critical,
            title:    "Docker API exposed without TLS (port 2375)".to_string(),
            detail:   "The Docker daemon is listening on TCP without TLS. Anyone who can \
                       reach this port has root-equivalent access to the host — they can \
                       mount the filesystem, run privileged containers, and escape to the \
                       underlying OS. Bind Docker to a Unix socket or enable mutual TLS \
                       (port 2376) and restrict access with firewall rules.".to_string(),
            mitre:    Some("T1610"),  // Deploy Container
            ports:    vec![2375],
        });
    }
    if is_open(2376) {
        return Some(Finding {
            severity: Severity::High,
            title:    "Docker API exposed with TLS (port 2376)".to_string(),
            detail:   "The Docker API is listening on the network with TLS enabled. \
                       This is better than plaintext but the API should not be publicly \
                       reachable. Verify mutual TLS client certificates are required, \
                       and firewall this port to known management IPs only.".to_string(),
            mitre:    Some("T1610"),
            ports:    vec![2376],
        });
    }
    None
}

fn check_metasploit_port(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(4444) { return None; }
    Some(Finding {
        severity: Severity::Critical,
        title:    "Port 4444 open — default Metasploit handler port".to_string(),
        detail:   "Port 4444 is the default listener port for Metasploit reverse shells \
                   and Meterpreter payloads. A production host should never have this port \
                   open. This may indicate active compromise, a misconfigured security tool, \
                   or a test payload that was not cleaned up.".to_string(),
        mitre:    Some("T1571"),  // Non-Standard Port (C2)
        ports:    vec![4444],
    })
}

fn check_rdp_exposed(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(3389) { return None; }
    Some(Finding {
        severity: Severity::High,
        title:    "RDP exposed (port 3389)".to_string(),
        detail:   "Remote Desktop Protocol is a common brute-force and credential-stuffing \
                   target. BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1181/1182) are \
                   wormable RDP vulnerabilities in unpatched Windows. RDP should be behind \
                   a VPN or restricted to known IPs — never open to the internet.".to_string(),
        mitre:    Some("T1021.001"),  // Remote Services: RDP
        ports:    vec![3389],
    })
}

fn check_smb_exposed(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(445) && !is_open(139) { return None; }
    let mut ports = vec![];
    if is_open(445) { ports.push(445); }
    if is_open(139) { ports.push(139); }
    Some(Finding {
        severity: Severity::High,
        title:    "SMB exposed (ports 445/139)".to_string(),
        detail:   "SMB is the attack surface exploited by EternalBlue (MS17-010), used in \
                   the WannaCry and NotPetya attacks. SMB should never be accessible from \
                   untrusted networks. If this is a legitimate file share, restrict access \
                   to specific subnets and ensure the host is patched for all SMB CVEs. \
                   Consider blocking at the perimeter unconditionally.".to_string(),
        mitre:    Some("T1021.002"),  // Remote Services: SMB/Windows Admin Shares
        ports,
    })
}

fn check_database_exposed(
    name: &str,
    port: u16,
    is_open: impl Fn(u16) -> bool,
) -> Option<Finding> {
    if !is_open(port) { return None; }

    // Redis-specific note: it has no authentication by default
    let detail = if port == 6379 {
        format!(
            "{name} (port {port}) is reachable from the network. Redis has no authentication \
             by default and allows arbitrary data reads, writes, and in some configurations \
             remote code execution via CONFIG SET and cron-based persistence. This should \
             only be accessible on localhost or a private network segment."
        )
    } else {
        format!(
            "{name} (port {port}) is reachable from the network. Databases should never be \
             directly exposed — they should sit behind an application server and be bound \
             to localhost or a private interface. Verify authentication is enforced, \
             connections are encrypted, and access is restricted by firewall rules."
        )
    };

    Some(Finding {
        severity: Severity::High,
        title:    format!("{name} database port exposed (port {port})"),
        detail,
        mitre:    Some("T1190"),  // Exploit Public-Facing Application
        ports:    vec![port],
    })
}

fn check_ftp(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(21) { return None; }
    Some(Finding {
        severity: Severity::Medium,
        title:    "FTP is open (port 21)".to_string(),
        detail:   "FTP transmits credentials and file contents in plaintext. It is also \
                   vulnerable to bounce attacks and passive mode firewall bypass. Use \
                   SFTP (over SSH, port 22) or FTPS (FTP over TLS) as replacements. \
                   If this is an anonymous FTP server, verify what files are accessible.".to_string(),
        mitre:    Some("T1048.003"),  // Exfiltration Over Unencrypted Protocol
        ports:    vec![21],
    })
}

fn check_snmp(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(161) { return None; }
    Some(Finding {
        severity: Severity::Medium,
        title:    "SNMP is open (port 161)".to_string(),
        detail:   "SNMP v1/v2c use community strings (typically 'public'/'private') instead \
                   of real authentication, and traffic is unencrypted. An attacker can use \
                   SNMP to enumerate the host's network interfaces, routing table, running \
                   processes, and installed software. Use SNMPv3 with authentication and \
                   encryption, or restrict this port to your NMS IP only.".to_string(),
        mitre:    Some("T1602.001"),  // Data from Configuration Repository: SNMP MIB Dump
        ports:    vec![161],
    })
}

fn check_vnc(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(5900) { return None; }
    Some(Finding {
        severity: Severity::Medium,
        title:    "VNC is open (port 5900)".to_string(),
        detail:   "VNC provides graphical remote access and is a common brute-force target. \
                   Many VNC servers are configured with weak or no passwords. Traffic may \
                   be unencrypted depending on the client/server version. Prefer RDP with \
                   NLA, or tunnel VNC over SSH rather than exposing port 5900 directly.".to_string(),
        mitre:    Some("T1021.005"),  // Remote Services: VNC
        ports:    vec![5900],
    })
}

fn check_ldap_unencrypted(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    // Port 389 = LDAP plaintext, port 636 = LDAPS (encrypted)
    if !is_open(389) { return None; }
    let detail = if is_open(636) {
        "Both LDAP (389) and LDAPS (636) are open. Ensure clients are configured to use \
         LDAPS only — the plaintext port 389 allows credential interception and LDAP \
         injection if not disabled.".to_string()
    } else {
        "LDAP is open on port 389 without the encrypted LDAPS port (636) also detected. \
         Directory queries and bind operations (logins) may be transmitted in plaintext. \
         Enable LDAPS and consider disabling port 389 entirely.".to_string()
    };
    Some(Finding {
        severity: Severity::Medium,
        title:    "Unencrypted LDAP open (port 389)".to_string(),
        detail,
        mitre:    Some("T1552.004"),  // Unsecured Credentials: Private Keys (LDAP binds)
        ports:    vec![389],
    })
}

fn check_kubernetes_api(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(6443) { return None; }
    Some(Finding {
        severity: Severity::High,
        title:    "Kubernetes API server exposed (port 6443)".to_string(),
        detail:   "The Kubernetes API server controls the entire cluster. If accessible from \
                   untrusted networks, a misconfigured RBAC policy or stolen service account \
                   token can give an attacker full cluster control — including the ability to \
                   deploy privileged containers and escape to host nodes. \
                   Restrict access to the API server to management networks only.".to_string(),
        mitre:    Some("T1613"),  // Container and Resource Discovery
        ports:    vec![6443],
    })
}

fn check_ssh_present(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(22) { return None; }
    Some(Finding {
        severity: Severity::Low,
        title:    "SSH is open (port 22)".to_string(),
        detail:   "SSH is expected on most Linux/Unix hosts. Verify that password \
                   authentication is disabled (PasswordAuthentication no in sshd_config), \
                   root login is disabled (PermitRootLogin no), and the service is \
                   restricted to known source IPs where possible. Consider moving to a \
                   non-standard port to reduce automated scan noise, though this is \
                   security through obscurity and not a substitute for proper config.".to_string(),
        mitre:    Some("T1021.004"),  // Remote Services: SSH
        ports:    vec![22],
    })
}

fn check_http_without_https(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    // Only flag if HTTP is open but HTTPS is NOT
    if !is_open(80) || is_open(443) { return None; }
    Some(Finding {
        severity: Severity::Low,
        title:    "HTTP open without HTTPS (port 80, no 443)".to_string(),
        detail:   "The host serves unencrypted HTTP without an HTTPS alternative. All \
                   traffic including session cookies, form submissions, and API tokens \
                   is visible to network observers. Enable TLS and redirect HTTP to HTTPS. \
                   Let's Encrypt provides free certificates.".to_string(),
        mitre:    Some("T1557"),  // Adversary-in-the-Middle
        ports:    vec![80],
    })
}

fn check_dev_ports_exposed(any_open: impl Fn(&[u16]) -> bool) -> Option<Finding> {
    let dev_ports: &[u16] = &[3000, 4200, 5173, 8888, 9000];
    if !any_open(dev_ports) { return None; }
    Some(Finding {
        severity: Severity::Low,
        title:    "Development server ports are open".to_string(),
        detail:   "Ports typically used by development frameworks (React, Vue, Vite, \
                   Jupyter, etc.) are reachable from the network. Dev servers generally \
                   run without authentication, TLS, or rate limiting. If this host is \
                   in a production or shared network, ensure these services are bound \
                   to localhost only.".to_string(),
        mitre:    Some("T1190"),
        ports:    dev_ports.to_vec(),
    })
}

fn check_mail_server(any_open: impl Fn(&[u16]) -> bool) -> Option<Finding> {
    let mail_ports: &[u16] = &[25, 110, 143, 465, 587, 993, 995];
    if !any_open(mail_ports) { return None; }
    Some(Finding {
        severity: Severity::Info,
        title:    "Mail server ports detected".to_string(),
        detail:   "One or more mail-related ports are open (SMTP, IMAP, POP3). \
                   Verify the server is not configured as an open relay (test with \
                   an MX lookup and relay test tool). Ensure all submission and \
                   retrieval ports use TLS — plain IMAP (143) and POP3 (110) transmit \
                   credentials in cleartext.".to_string(),
        mitre:    Some("T1114.002"),  // Email Collection: Remote Email Collection
        ports:    mail_ports.to_vec(),
    })
}

fn check_jupyter(is_open: impl Fn(u16) -> bool) -> Option<Finding> {
    if !is_open(8888) { return None; }
    Some(Finding {
        severity: Severity::High,
        title:    "Jupyter Notebook likely exposed (port 8888)".to_string(),
        detail:   "Port 8888 is the default Jupyter Notebook port. Jupyter can execute \
                   arbitrary code on the host. If exposed without a password or token, \
                   an attacker has full remote code execution on the underlying OS. \
                   Many Jupyter deployments on cloud VMs have been exploited for \
                   cryptomining. Bind to localhost and use SSH tunneling for remote access.".to_string(),
        mitre:    Some("T1059"),  // Command and Scripting Interpreter
        ports:    vec![8888],
    })
}


// ============================================================
// check_banner_issues
//
// Inspects the actual banner text for version strings and
// patterns that indicate specific vulnerabilities or misconfigs.
//
// This is called per open port that has a banner. It returns
// at most one Finding per port — the most notable thing found.
// ============================================================
fn check_banner_issues(port: u16, banner: &str) -> Option<Finding> {
    let banner_lower = banner.to_lowercase();

    // SSH version detection — old versions have known CVEs
    if port == 22 && banner_lower.contains("ssh-") {
        // OpenSSH versions before 8.0 have various CVEs
        // We check for obviously old major versions
        if banner_lower.contains("openssh_7.")
            || banner_lower.contains("openssh_6.")
            || banner_lower.contains("openssh_5.")
        {
            return Some(Finding {
                severity: Severity::Medium,
                title:    format!("Outdated OpenSSH version detected"),
                detail:   format!(
                    "Banner reports: \"{banner}\". OpenSSH versions before 8.x have \
                     known vulnerabilities including user enumeration (CVE-2018-15919) \
                     and memory issues. Upgrade to the latest OpenSSH release."
                ),
                mitre:    Some("T1190"),
                ports:    vec![port],
            });
        }

        // Check for non-OpenSSH SSH servers (Dropbear, libssh, etc.)
        if !banner_lower.contains("openssh") {
            return Some(Finding {
                severity: Severity::Info,
                title:    "Non-OpenSSH server detected".to_string(),
                detail:   format!(
                    "Banner reports: \"{banner}\". This is not OpenSSH — it may be \
                     Dropbear (common on embedded devices/routers) or another implementation. \
                     Verify this is expected for this host type."
                ),
                mitre:    None,
                ports:    vec![port],
            });
        }
    }

    // FTP anonymous login hint
    if port == 21 && banner_lower.contains("anonymous") {
        return Some(Finding {
            severity: Severity::High,
            title:    "FTP anonymous login may be enabled".to_string(),
            detail:   format!(
                "Banner mentions anonymous access: \"{banner}\". If anonymous FTP is \
                 enabled, any user can read (and possibly write) files without credentials. \
                 Audit what is accessible and disable anonymous login unless explicitly required."
            ),
            mitre:    Some("T1078.001"),  // Valid Accounts: Default Accounts
            ports:    vec![port],
        });
    }

    // SMTP open relay hint
    if port == 25 && (banner_lower.contains("relay") || banner_lower.contains("open")) {
        return Some(Finding {
            severity: Severity::High,
            title:    "SMTP banner suggests possible open relay".to_string(),
            detail:   format!(
                "SMTP banner: \"{banner}\". The banner text may indicate an open relay \
                 configuration. Test with an SMTP relay checker. Open relays are exploited \
                 for spam and phishing campaigns and will result in IP blacklisting."
            ),
            mitre:    Some("T1534"),  // Internal Spearphishing
            ports:    vec![port],
        });
    }

    // HTTP server version disclosure
    if (port == 80 || port == 8080 || port == 443) && banner_lower.contains("server:") {
        return Some(Finding {
            severity: Severity::Info,
            title:    "Web server version disclosed in banner".to_string(),
            detail:   format!(
                "HTTP response includes Server header: \"{banner}\". Version disclosure \
                 helps attackers identify exploitable versions. Set 'ServerTokens Prod' \
                 (Apache) or 'server_tokens off' (nginx) to suppress version information."
            ),
            mitre:    Some("T1592.002"),  // Gather Victim Host Information
            ports:    vec![port],
        });
    }

    None
}


// ============================================================
// render_report  (public — called from main.rs)
//
// Takes a HostReport and prints it to stdout with colors,
// severity badges, MITRE tags, and the narrative summary.
// ============================================================
pub fn render_report(report: &HostReport) {
    // --------------------------------------------------------
    // Header block
    // --------------------------------------------------------
    println!("\n{}", "━".repeat(72).truecolor(60, 60, 60));
    println!(
        "{} {} {}",
        "🐽 SNIFFSNORF ANALYSIS".cyan().bold(),
        "·".truecolor(80, 80, 80),
        report.host.white().bold(),
    );
    println!(
        "   {} {}",
        "Host type:".truecolor(120, 120, 120),
        report.host_type.description().white(),
    );
    println!(
        "   {} {} open port{}",
        "Surface:".truecolor(120, 120, 120),
        report.open_ports.len().to_string().yellow().bold(),
        if report.open_ports.len() == 1 { "" } else { "s" },
    );
    println!("{}", "━".repeat(72).truecolor(60, 60, 60));

    // --------------------------------------------------------
    // Narrative summary paragraph
    // --------------------------------------------------------
    println!("\n{}", "SUMMARY".truecolor(160, 160, 160));
    println!("{}", wrap_text(&report.summary, 70));

    // --------------------------------------------------------
    // Findings list
    // --------------------------------------------------------
    if report.findings.is_empty() {
        println!(
            "\n{} No notable findings in the scanned range.",
            "✓".green()
        );
        return;
    }

    println!("\n{}", "FINDINGS".truecolor(160, 160, 160));

    for (i, finding) in report.findings.iter().enumerate() {
        println!();

        // Finding number + severity badge + title
        println!(
            "  {}  {} {}",
            format!("[{}]", i + 1).truecolor(100, 100, 100),
            finding.severity.badge(),
            finding.title.white().bold(),
        );

        // Affected ports
        let port_str: Vec<String> = finding.ports.iter().map(|p| p.to_string()).collect();
        println!(
            "       {} {}",
            "Ports:".truecolor(120, 120, 120),
            port_str.join(", ").yellow(),
        );

        // MITRE ATT&CK tag if present
        if let Some(mitre) = finding.mitre {
            println!(
                "       {} {}",
                "MITRE:".truecolor(120, 120, 120),
                mitre.truecolor(150, 120, 200),
            );
        }

        // Detail paragraph, indented and word-wrapped
        println!(
            "       {}\n{}",
            "Detail:".truecolor(120, 120, 120),
            wrap_and_indent(&finding.detail, 70, 7),
        );
    }

    println!("{}", "━".repeat(72).truecolor(60, 60, 60));

    // Severity count summary at the bottom
    let counts = [
        (Severity::Critical, "critical"),
        (Severity::High,     "high"),
        (Severity::Medium,   "medium"),
        (Severity::Low,      "low"),
        (Severity::Info,     "info"),
    ];

    print!("  Findings: ");
    for (sev, label) in &counts {
        let n = report.findings.iter().filter(|f| &f.severity == sev).count();
        if n > 0 {
            print!("{} {}  ", n.to_string().bold(), label.truecolor(140, 140, 140));
        }
    }
    println!();
}


// ============================================================
// Text formatting helpers
// ============================================================

// Word-wrap a string to `width` characters, preserving words.
fn wrap_text(text: &str, width: usize) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for word in text.split_whitespace() {
        if line_len + word.len() + 1 > width && line_len > 0 {
            result.push('\n');
            line_len = 0;
        }
        if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }
    result
}

// Word-wrap and indent every line by `indent` spaces.
fn wrap_and_indent(text: &str, width: usize, indent: usize) -> String {
    let prefix = " ".repeat(indent);
    wrap_text(text, width)
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}


// ============================================================
// render_report_plain  (public — called from main.rs for .txt output)
//
// Same structure as render_report() but returns a plain String
// with no ANSI color codes. Used when writing .txt files.
// ============================================================
pub fn render_report_plain(report: &HostReport) -> String {
    let mut out = String::new();
    let divider = "━".repeat(72);

    out.push('\n');
    out.push_str(&divider);
    out.push('\n');
    out.push_str(&format!(
        "🐽 SNIFFSNORF ANALYSIS · {}\n",
        report.host
    ));
    out.push_str(&format!(
        "   Host type: {}\n",
        report.host_type.description()
    ));
    out.push_str(&format!(
        "   Surface: {} open port{}\n",
        report.open_ports.len(),
        if report.open_ports.len() == 1 { "" } else { "s" }
    ));
    out.push_str(&divider);
    out.push('\n');

    out.push_str("\nSUMMARY\n");
    out.push_str(&wrap_text(&report.summary, 70));
    out.push('\n');

    if report.findings.is_empty() {
        out.push_str("\n✓ No notable findings in the scanned range.\n");
    } else {
        out.push_str("\nFINDINGS\n");

        for (i, finding) in report.findings.iter().enumerate() {
            out.push('\n');
            out.push_str(&format!(
                "  [{}]  {}  {}\n",
                i + 1,
                finding.severity.label(),
                finding.title
            ));

            let port_str: Vec<String> = finding.ports.iter().map(|p| p.to_string()).collect();
            out.push_str(&format!("       Ports:  {}\n", port_str.join(", ")));

            if let Some(mitre) = finding.mitre {
                out.push_str(&format!("       MITRE:  {mitre}\n"));
            }

            out.push_str("       Detail:\n");
            out.push_str(&wrap_and_indent(&finding.detail, 70, 7));
            out.push('\n');
        }
    }

    out.push_str(&divider);
    out.push('\n');

    let counts = [
        (Severity::Critical, "critical"),
        (Severity::High,     "high"),
        (Severity::Medium,   "medium"),
        (Severity::Low,      "low"),
        (Severity::Info,     "info"),
    ];

    out.push_str("  Findings: ");
    for (sev, label) in &counts {
        let n = report.findings.iter().filter(|f| &f.severity == sev).count();
        if n > 0 {
            out.push_str(&format!("{n} {label}  "));
        }
    }
    out.push('\n');

    out
}
