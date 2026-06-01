// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::SystemTime;

/// Extract the AWS region from a standard AWS hostname.
/// Finds the label immediately before `amazonaws.com`.
/// Works for both `<service>.<region>.amazonaws.com` and
/// `<bucket>.<service>.<region>.amazonaws.com`.
pub fn extract_aws_region(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 && parts[parts.len() - 2] == "amazonaws" && parts[parts.len() - 1] == "com"
    {
        Some(parts[parts.len() - 3].to_string())
    } else {
        None
    }
}

fn is_aws_auth_header(lower: &str) -> bool {
    matches!(
        lower,
        "authorization" | "x-amz-date" | "x-amz-security-token" | "x-amz-content-sha256"
    )
}

fn is_hop_by_hop_header(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "accept-encoding"
    )
}

/// Strip AWS auth headers from raw HTTP request bytes.
///
/// Removes Authorization, X-Amz-Date, X-Amz-Security-Token, and
/// X-Amz-Content-Sha256 headers so the request can pass through the
/// proxy's fail-closed placeholder scan before `SigV4` re-signing.
pub fn strip_aws_headers(raw: &[u8]) -> Vec<u8> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let lines: Vec<&str> = header_str.split("\r\n").collect();

    let mut output = Vec::with_capacity(raw.len());

    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            output.extend_from_slice(line.as_bytes());
            output.extend_from_slice(b"\r\n");
            continue;
        }
        if line.is_empty() {
            break;
        }
        if let Some((k, _)) = line.split_once(':')
            && is_aws_auth_header(&k.trim().to_ascii_lowercase())
        {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");

    if header_end < raw.len() {
        output.extend_from_slice(&raw[header_end..]);
    }

    output
}

/// Apply `SigV4` signing to a raw HTTP request buffer.
///
/// Strips existing AWS auth headers, computes a new `SigV4` signature using
/// the official `aws-sigv4` crate, and returns the rewritten request bytes.
pub fn apply_sigv4_to_request(
    raw: &[u8],
    host: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Vec<u8> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);

    let body = if header_end < raw.len() {
        &raw[header_end..]
    } else {
        &[]
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let lines: Vec<&str> = header_str.split("\r\n").collect();

    let (method, path) = lines.first().map_or(("GET", "/"), |first_line| {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            (parts[0], parts[1])
        } else {
            ("GET", "/")
        }
    });

    // Preserve all original headers except AWS auth headers (which we
    // regenerate) and hop-by-hop headers (which the proxy or transport may
    // modify between signing and delivery, breaking the signature).
    let mut existing_headers: Vec<(String, String)> = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let lower = k.trim().to_ascii_lowercase();
            if is_aws_auth_header(&lower) || is_hop_by_hop_header(&lower) {
                continue;
            }
            existing_headers.push((lower, v.trim().to_string()));
        }
    }

    let uri = format!("https://{host}{path}");

    let identity: Identity = Credentials::new(
        access_key,
        secret_key,
        session_token.map(ToString::to_string),
        None,
        "openshell",
    )
    .into();

    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .expect("all required signing params provided")
        .into();

    let signable_request = SignableRequest::new(
        method,
        &uri,
        existing_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .expect("valid signable request");

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .expect("signing should not fail with valid inputs")
        .into_parts();

    // Rebuild the request with signed headers
    let mut output = Vec::with_capacity(raw.len() + 256);

    // Request line
    if let Some(first_line) = lines.first() {
        output.extend_from_slice(first_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Existing headers (filtered)
    for (k, v) in &existing_headers {
        output.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }

    // Signed headers from the SDK
    for (name, value) in instructions.headers() {
        output.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    // End of headers
    output.extend_from_slice(b"\r\n");

    // Body
    output.extend_from_slice(body);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_region_from_hostname() {
        let region = extract_aws_region("bedrock-runtime.us-east-2.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-2");
    }

    #[test]
    fn extract_region_from_sts_hostname() {
        let region = extract_aws_region("sts.us-east-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn extract_region_from_s3_virtual_hosted_hostname() {
        let region = extract_aws_region("my-bucket.s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn non_aws_hostname_returns_none() {
        assert!(extract_aws_region("api.anthropic.com").is_none());
    }

    #[test]
    fn sign_produces_valid_format() {
        let raw = b"POST /model/us.anthropic.claude-sonnet-4-6/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        );
        assert!(result_str.contains("x-amz-content-sha256: "));
        assert!(result_str.contains("x-amz-date: "));
        assert!(!result_str.contains("x-amz-security-token"));
    }

    #[test]
    fn sign_with_session_token() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "ASIAEXAMPLE",
            "secret",
            Some("FwoGZXIvYXdzEBYaDH+session+token"),
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/"));
        assert!(result_str.contains("x-amz-security-token: FwoGZXIvYXdzEBYaDH+session+token"));
    }

    #[test]
    fn sign_preserves_s3_headers_and_strips_hop_by_hop() {
        let raw = b"PUT /object.txt HTTP/1.1\r\nHost: my-bucket.s3.us-east-1.amazonaws.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nx-amz-acl: private\r\nx-amz-server-side-encryption: AES256\r\nRange: bytes=0-99\r\nConnection: keep-alive\r\nAccept-Encoding: gzip\r\nProxy-Connection: keep-alive\r\n\r\nhello";
        let result = apply_sigv4_to_request(
            raw,
            "my-bucket.s3.us-east-1.amazonaws.com",
            "us-east-1",
            "s3",
            "AKIATEST",
            "secret",
            None,
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("x-amz-acl: private"));
        assert!(result_str.contains("x-amz-server-side-encryption: AES256"));
        assert!(result_str.contains("range: bytes=0-99"));
        assert!(!result_str.contains("connection:"));
        assert!(!result_str.contains("accept-encoding:"));
        assert!(!result_str.contains("proxy-connection:"));
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256"));
    }

    #[test]
    fn apply_sigv4_rewrites_request() {
        let raw = b"POST /model/test/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-2.amazonaws.com\r\nContent-Type: application/json\r\nAuthorization: AWS4-HMAC-SHA256 old-invalid-sig\r\nX-Amz-Date: old-date\r\n\r\n{}";
        let result = apply_sigv4_to_request(
            raw,
            "bedrock-runtime.us-east-2.amazonaws.com",
            "us-east-2",
            "bedrock",
            "AKIATEST",
            "secret",
            None,
        );
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("authorization: AWS4-HMAC-SHA256 Credential=AKIATEST/"));
        assert!(!result_str.contains("old-invalid-sig"));
        assert!(!result_str.contains("old-date"));
    }
}
