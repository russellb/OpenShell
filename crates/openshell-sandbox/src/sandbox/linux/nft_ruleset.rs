// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! nftables ruleset generation for sandbox network bypass enforcement.
//!
//! This module provides pure functions to generate nftables rulesets that enforce
//! the sandbox network policy: all traffic must go through the proxy, with bypass
//! attempts logged and rejected.

/// Generate a complete nftables ruleset for sandbox network bypass enforcement.
///
/// Creates an `inet` family table (handles both IPv4 and IPv6) with rules that:
/// 1. Accept traffic to the proxy (IPv4 only)
/// 2. Accept loopback traffic
/// 3. Accept established/related connections
/// 4. Log and reject TCP bypass attempts (both IPv4 and IPv6)
/// 5. Log and reject UDP bypass attempts (both IPv4 and IPv6)
///
/// # Arguments
///
/// * `host_ip` - The IPv4 address of the host proxy (e.g., "10.0.2.2")
/// * `proxy_port` - The TCP port of the proxy (e.g., 8080)
/// * `log_prefix` - The prefix for netfilter log messages (e.g., "BYPASS: ")
///
/// # Returns
///
/// A string containing the complete nftables ruleset, ready to be loaded via `nft -f -`
///
pub fn generate_bypass_ruleset(host_ip: &str, proxy_port: u16, log_prefix: &str) -> String {
    format!(
        r#"table inet openshell_bypass {{
    chain output {{
        type filter hook output priority 0; policy accept;

        # Rule 1: ACCEPT traffic to proxy (IPv4 only)
        ip daddr {host_ip} tcp dport {proxy_port} accept

        # Rule 2: ACCEPT loopback
        oifname "lo" accept

        # Rule 3: ACCEPT established/related
        ct state established,related accept

        # Rule 4a: LOG TCP SYN bypass attempts (rate-limited)
        tcp flags syn limit rate 5/second burst 10 packets log prefix "{log_prefix}" group 0
        # Rule 4b: REJECT TCP (IPv4)
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        # Rule 4c: REJECT TCP (IPv6)
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable

        # Rule 5a: LOG UDP bypass attempts (rate-limited)
        meta l4proto udp limit rate 5/second burst 10 packets log prefix "{log_prefix}" group 0
        # Rule 5b: REJECT UDP (IPv4)
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        # Rule 5c: REJECT UDP (IPv6)
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_bypass_ruleset_with_proxy_rule() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, "BYPASS: ");

        // Basic smoke test: ruleset should contain key elements
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("10.0.2.2"));
        assert!(ruleset.contains("8080"));
        assert!(ruleset.contains("BYPASS: "));
    }

    #[test]
    fn ruleset_has_inet_family_table_and_output_chain() {
        let ruleset = generate_bypass_ruleset("192.168.1.1", 3128, "TEST: ");

        // Validate structure: must use inet family and output chain
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("type filter hook output priority 0; policy accept;"));
    }

    #[test]
    fn proxy_accept_rule_uses_provided_ip_and_port() {
        let ruleset = generate_bypass_ruleset("172.16.0.1", 9999, "PREFIX: ");

        // Verify parameterization: IP and port are correctly embedded
        assert!(ruleset.contains("ip daddr 172.16.0.1 tcp dport 9999 accept"));
    }

    #[test]
    fn log_prefix_embedded_in_both_tcp_and_udp_rules() {
        let ruleset = generate_bypass_ruleset("10.0.0.1", 8080, "CUSTOM_PREFIX: ");

        // Count occurrences: log prefix should appear exactly twice (TCP and UDP)
        let count = ruleset.matches("log prefix \"CUSTOM_PREFIX:\"").count();
        assert_eq!(
            count, 2,
            "Log prefix should appear exactly twice (TCP and UDP rules)"
        );
    }

    #[test]
    fn rules_are_ordered_accept_then_log_then_reject() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, "BYPASS: ");

        // Validate ordering: accept rules before log/reject rules
        let proxy_accept_pos = ruleset.find("ip daddr").unwrap();
        let loopback_pos = ruleset.find("oifname \"lo\"").unwrap();
        let established_pos = ruleset.find("ct state established,related").unwrap();
        let tcp_log_pos = ruleset.find("tcp flags syn limit rate").unwrap();
        let tcp_reject_ipv4_pos = ruleset
            .find("meta nfproto ipv4 meta l4proto tcp reject")
            .unwrap();
        let tcp_reject_ipv6_pos = ruleset
            .find("meta nfproto ipv6 meta l4proto tcp reject")
            .unwrap();

        // Accept rules should come before log/reject rules
        assert!(
            proxy_accept_pos < tcp_log_pos,
            "Proxy accept should come before TCP log"
        );
        assert!(
            loopback_pos < tcp_log_pos,
            "Loopback accept should come before TCP log"
        );
        assert!(
            established_pos < tcp_log_pos,
            "Established accept should come before TCP log"
        );

        // Log should come before reject
        assert!(
            tcp_log_pos < tcp_reject_ipv4_pos,
            "TCP log should come before TCP IPv4 reject"
        );
        assert!(
            tcp_log_pos < tcp_reject_ipv6_pos,
            "TCP log should come before TCP IPv6 reject"
        );
    }

    #[test]
    fn both_ipv4_and_ipv6_reject_types_are_present() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, "BYPASS: ");

        // Verify both ICMP and ICMPv6 reject types exist
        assert!(
            ruleset.contains("reject with icmp type port-unreachable"),
            "IPv4 ICMP reject missing"
        );
        assert!(
            ruleset.contains("reject with icmpv6 type port-unreachable"),
            "IPv6 ICMPv6 reject missing"
        );

        // Count: should have 2 icmp rejects (TCP + UDP) and 2 icmpv6 rejects (TCP + UDP)
        let icmp_count = ruleset
            .matches("reject with icmp type port-unreachable")
            .count();
        let icmpv6_count = ruleset
            .matches("reject with icmpv6 type port-unreachable")
            .count();

        assert_eq!(icmp_count, 2, "Should have 2 IPv4 ICMP rejects (TCP + UDP)");
        assert_eq!(
            icmpv6_count, 2,
            "Should have 2 IPv6 ICMPv6 rejects (TCP + UDP)"
        );
    }

    #[test]
    fn rate_limiting_matches_original_iptables_semantics() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080, "BYPASS: ");

        // Verify rate limiting: 5/second burst 10 packets (matches original iptables)
        assert!(ruleset.contains("limit rate 5/second burst 10 packets"));

        // Count: should appear twice (TCP and UDP)
        let rate_limit_count = ruleset
            .matches("limit rate 5/second burst 10 packets")
            .count();
        assert_eq!(
            rate_limit_count, 2,
            "Rate limiting should appear twice (TCP and UDP)"
        );
    }
}
