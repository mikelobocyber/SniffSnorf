// ============================================================
// cidr.rs — Target resolution and CIDR expansion
//
// This module turns whatever the user typed as `<TARGET>` into
// a list of host strings that we can connect to.
//
// It handles three input formats:
//   Bare IP:   "192.168.1.1"     → ["192.168.1.1"]
//   Hostname:  "scanme.nmap.org" → ["scanme.nmap.org"]
//   CIDR:      "192.168.1.0/24"  → ["192.168.1.0", ..., "192.168.1.255"]
//
// DNS resolution for hostnames happens at connect time inside
// tokio — we don't need to resolve them here.
//
// Unit tests live at the bottom of this file (`cargo test`).
// ============================================================

use std::net::IpAddr;


// ============================================================
// resolve_targets  (public — called from main.rs)
//
// Entry point for this module. Takes the raw target string and
// returns a Vec of strings to scan, or an error message.
//
// The return type `Result<Vec<String>, String>` means:
//   Ok(Vec<String>)  — success, here are your targets
//   Err(String)      — failure, here's a human-readable message
// ============================================================
pub fn resolve_targets(input: &str) -> Result<Vec<String>, String> {

    // Check for a slash — that's the CIDR prefix separator.
    // "192.168.1.0/24" contains a slash; "192.168.1.1" does not.
    if input.contains('/') {
        return expand_cidr(input);
    }

    // Try to parse as a bare IP address (IPv4 or IPv6).
    // `.parse::<IpAddr>()` returns Ok(IpAddr) on success.
    // If it succeeds, wrap it in a one-element Vec and return.
    if let Ok(addr) = input.parse::<IpAddr>() {
        return Ok(vec![addr.to_string()]);
    }

    // Neither CIDR nor bare IP — treat it as a hostname.
    // We pass it through as-is; tokio will do DNS lookup when
    // TcpStream::connect() is called later.
    Ok(vec![input.to_string()])
}


// ============================================================
// expand_cidr  (private — only used inside this module)
//
// Takes a CIDR string like "192.168.1.0/24" and returns a Vec
// containing every IP address in that range as strings.
//
// How CIDR works:
//   An IPv4 address is 32 bits. A CIDR prefix like /24 means
//   the first 24 bits are the "network" part and the remaining
//   8 bits are the "host" part.
//
//   /24 → 2^8  = 256  hosts
//   /28 → 2^4  = 16   hosts
//   /30 → 2^2  = 4    hosts
//   /32 → 2^0  = 1    host  (a single IP)
//
// We compute the base address, mask off the host bits, then
// iterate over all possible host values and convert each to
// an IP string.
// ============================================================
fn expand_cidr(cidr: &str) -> Result<Vec<String>, String> {

    // Split "192.168.1.0/24" into ["192.168.1.0", "24"]
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR notation: '{cidr}' — expected format: x.x.x.x/prefix"));
    }

    // Parse the base IP address (the part before the slash)
    let base: std::net::Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("invalid IPv4 address: '{}' — SniffSnorf only supports IPv4 CIDR", parts[0]))?;

    // Parse the prefix length (the number after the slash)
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("invalid prefix length: '{}' — must be a number 16–32", parts[1]))?;

    // Validate prefix range — IPv4 prefixes are 0–32
    if prefix > 32 {
        return Err(format!("prefix /{prefix} is out of range — maximum is /32"));
    }

    // Safety guard: refuse to expand ranges larger than /16.
    //
    // /16 = 65,536 hosts. /8 = 16,777,216 hosts.
    // Accidentally scanning a /8 would be both slow and dangerous.
    // We make the user be explicit about large ranges.
    //
    // To remove this guard: delete the `if prefix < 16` block.
    if prefix < 16 {
        let host_count = 1u64 << (32 - prefix);
        return Err(format!(
            "CIDR /{prefix} would generate {host_count} hosts — \
             SniffSnorf limits CIDR expansion to /16 (65,536 hosts). \
             Use a more specific range, or extend the limit in cidr.rs."
        ));
    }

    // --------------------------------------------------------
    // Core CIDR math
    //
    // `u32::from(base)` — convert the Ipv4Addr to a raw u32.
    // An IPv4 address is just 4 bytes; treating it as a u32
    // lets us do arithmetic on it.
    //
    // host_bits: how many bits are left over for host addresses
    // count: 2^host_bits = total number of addresses in the range
    //
    // network: the base address with host bits zeroed out.
    //   Example: 192.168.1.100/24
    //     base_u32 = 0xC0A80164
    //     !0u32 << 8 = 0xFFFFFF00  (the network mask)
    //     network   = 0xC0A80100   (192.168.1.0)
    // --------------------------------------------------------
    let host_bits = 32 - prefix;
    let count = 1u32 << host_bits;  // Number of addresses in range
    let base_u32 = u32::from(base);

    // Apply the network mask to zero out host bits.
    // Special-case /32: shifting by 32 would overflow a u32.
    let network = if prefix == 0 {
        0u32
    } else {
        base_u32 & (!0u32 << host_bits)
    };

    // Pre-allocate the Vec with the exact capacity we need.
    // This avoids repeated reallocation as we push.
    let mut addrs = Vec::with_capacity(count as usize);

    // Iterate from 0 to count-1, adding each offset to the
    // network base address to get each host address.
    for i in 0..count {
        // `network + i` is now the u32 representation of this host IP.
        // `Ipv4Addr::from(u32)` converts it back to a proper IP.
        let ip = std::net::Ipv4Addr::from(network + i);
        addrs.push(ip.to_string());
    }

    Ok(addrs)
}


// ============================================================
// Unit tests
//
// `cargo test` runs these. They live in this file so they have
// access to the private `expand_cidr` function.
//
// `#[cfg(test)]` means this block is only compiled during tests,
// not in the release binary.
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;  // Import everything from the parent module

    #[test]
    fn test_single_ip_passthrough() {
        let result = resolve_targets("192.168.1.1").unwrap();
        assert_eq!(result, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_hostname_passthrough() {
        // Hostnames pass through unchanged; DNS happens at connect time
        let result = resolve_targets("localhost").unwrap();
        assert_eq!(result, vec!["localhost"]);
    }

    #[test]
    fn test_cidr_slash32_is_one_host() {
        // /32 means exactly one address
        let result = resolve_targets("10.0.0.1/32").unwrap();
        assert_eq!(result, vec!["10.0.0.1"]);
    }

    #[test]
    fn test_cidr_slash30_is_four_hosts() {
        // /30 = 4 addresses (commonly used for point-to-point links)
        let result = resolve_targets("10.0.0.0/30").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], "10.0.0.0");
        assert_eq!(result[3], "10.0.0.3");
    }

    #[test]
    fn test_cidr_slash24_is_256_hosts() {
        // /24 = a typical LAN subnet
        let result = resolve_targets("192.168.1.0/24").unwrap();
        assert_eq!(result.len(), 256);
        assert_eq!(result[0], "192.168.1.0");
        assert_eq!(result[255], "192.168.1.255");
    }

    #[test]
    fn test_cidr_too_large_is_rejected() {
        // /8 would generate 16M hosts — should be rejected
        assert!(resolve_targets("10.0.0.0/8").is_err());
    }

    #[test]
    fn test_cidr_network_bits_are_masked() {
        // Even if user gives a host address, we mask to network
        // 10.0.0.5/30 → network is 10.0.0.4
        let result = resolve_targets("10.0.0.5/30").unwrap();
        assert_eq!(result[0], "10.0.0.4");
        assert_eq!(result.len(), 4);
    }
}
