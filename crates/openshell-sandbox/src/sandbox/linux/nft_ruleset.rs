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
pub fn generate_bypass_ruleset(host_ip: &str, proxy_port: u16) -> String {
    format!(
        r#"table inet openshell_bypass {{
    chain output {{
        type filter hook output priority 0; policy accept;

        ip daddr {host_ip} tcp dport {proxy_port} accept
        oifname "lo" accept
        ct state established,related accept
        meta nfproto ipv4 meta l4proto tcp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto tcp reject with icmpv6 type port-unreachable
        meta nfproto ipv4 meta l4proto udp reject with icmp type port-unreachable
        meta nfproto ipv6 meta l4proto udp reject with icmpv6 type port-unreachable
    }}
}}
"#
    )
}

/// Generate optional nftables log rules for bypass diagnostics.
///
/// These rules are loaded separately from the base ruleset because the
/// nftables `log` expression requires kernel support (`nft_log` module)
/// that may not be available in all environments. If loading fails, the
/// base REJECT rules still provide fast-fail UX.
pub fn generate_bypass_log_rules(log_prefix: &str) -> String {
    format!(
        r#"table inet openshell_bypass {{
    chain output {{
        tcp flags syn limit rate 5/second burst 10 packets log prefix "{log_prefix}"
        meta l4proto udp limit rate 5/second burst 10 packets log prefix "{log_prefix}"
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
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080);
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("ip daddr 10.0.2.2 tcp dport 8080 accept"));
    }

    #[test]
    fn ruleset_has_inet_family_table_and_output_chain() {
        let ruleset = generate_bypass_ruleset("192.168.1.1", 3128);
        assert!(ruleset.contains("table inet openshell_bypass"));
        assert!(ruleset.contains("type filter hook output priority 0; policy accept;"));
    }

    #[test]
    fn proxy_accept_rule_uses_provided_ip_and_port() {
        let ruleset = generate_bypass_ruleset("172.16.0.1", 9999);
        assert!(ruleset.contains("ip daddr 172.16.0.1 tcp dport 9999 accept"));
    }

    #[test]
    fn rules_are_ordered_accept_then_reject() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080);
        let proxy_pos = ruleset.find("ip daddr").unwrap();
        let lo_pos = ruleset.find("oifname \"lo\"").unwrap();
        let ct_pos = ruleset.find("ct state established,related").unwrap();
        let reject_pos = ruleset.find("reject with icmp type").unwrap();

        assert!(proxy_pos < lo_pos);
        assert!(lo_pos < ct_pos);
        assert!(ct_pos < reject_pos);
    }

    #[test]
    fn both_ipv4_and_ipv6_reject_types_are_present() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080);
        let icmp_count = ruleset
            .matches("reject with icmp type port-unreachable")
            .count();
        let icmpv6_count = ruleset
            .matches("reject with icmpv6 type port-unreachable")
            .count();
        assert_eq!(icmp_count, 2, "need IPv4 ICMP rejects for TCP + UDP");
        assert_eq!(icmpv6_count, 2, "need IPv6 ICMPv6 rejects for TCP + UDP");
    }

    #[test]
    fn base_ruleset_has_no_log_rules() {
        let ruleset = generate_bypass_ruleset("10.0.2.2", 8080);
        assert!(
            !ruleset.contains("log prefix"),
            "base ruleset must not contain log rules (they are loaded separately)"
        );
    }

    #[test]
    fn log_rules_contain_prefix_for_tcp_and_udp() {
        let rules = generate_bypass_log_rules("openshell:bypass:test:");
        let count = rules
            .matches("log prefix \"openshell:bypass:test:\"")
            .count();
        assert_eq!(count, 2, "need log rules for both TCP and UDP");
        assert!(rules.contains("tcp flags syn limit rate 5/second burst 10 packets"));
        assert!(rules.contains("meta l4proto udp limit rate 5/second burst 10 packets"));
    }
}
