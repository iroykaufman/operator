// SPDX-FileCopyrightText: Chirag Rao <crao@redhat.com>
//
// SPDX-License-Identifier: MIT

//! Fedora Crypto Policies (<https://gitlab.com/redhat-crypto/fedora-crypto-policies>) only curates policy for an allowlist of backends (OpenSSL, GnuTLS, NSS, libkrb5, ...)
//! Any crate that reimplements its own crypto/TLS bypasses the system-wide policy and should be blocked.

//! What this test does:
//! Uses `cargo tree -e normal` to find every crate that actually ships in the built binaries (excluding dev-/build-only dependencies)
//! `cargo metadata` to look up each one's crates.io categories/keywords. Each crypto crate available in Cargo ecosystem is blocked by default, unless allowlisted.
//! This test can run air-gapped as all information about the Cargo crates is available in the metadata and the .lock files.

use serde_json::Value;
use std::collections::HashSet;
use std::process::Command;

// Crypto crates allowlisted by Fedora Crypto Policies having approved policies and backends.
/// Crates having only types/errors rather than a crypto/TLS implementation of their own are also allowed (rustls-pki-types).
const ALLOWED_CRYPTO_CRATES: &[&str] = &[
    "openssl",
    "openssl-sys",
    "rustls-pki-types",
    "sequoia-openpgp",
    // Dependencies of openssl, no harm in allowlisting these.
    "openssl-probe",
    "openssl-macros",
    // Pulled in by jsonwebtoken; formats & traits only
    "digest",
    "pem",
    "signature",
    // Pulled in by kube-client; API only
    "secrecy",
    "zeroize",
    "zeroize_derive",
    // Pulled in by kbs-client; formats, traits & API only
    "aead",
    "base16ct",
    "block-buffer",
    "cipher",
    "constant_time_eq",
    "const-oid",
    "cose-rust",
    "crypto-bigint",
    "crypto-common",
    "ctr",
    "der",
    "digest",
    "elliptic-curve",
    "hmac",
    "pem-rfc7468",
    "pkcs1",
    "pkcs8",
    "sec1",
    "spki",
    "universal-hash",
    "subtle",
    // Pulled in by kbs-client via jwt-simple. TODO see if that can be replaced with
    // jsonwebtoken:openssl entirely, which kbs-client already uses elsewhere.
    "ct-codecs",
    "ed25519-compact",
    "jwt-simple",
    "hmac-sha1-compact",
    "hmac-sha256",
    "hmac-sha512",
    "k256",
    "p384",
    "superboring",
    // Pulled in by kbs-client. Not used for network TLS but
    // TODO better rely on verified implementations.
    "aes",
    "aes-gcm",
    "aes-kw",
    "aws-lc-rs",
    "chacha20",
    "concat-kdf",
    "ecdsa",
    "ghash",
    "hkdf",
    "p256",
    "p521",
    "polyval",
    "ppv-lite86",
    "primeorder",
    "rfc6979",
    "rsa",
    "sha2",
    "siphasher",
    "sm3",
    // Pulled in by authenticode. Formats only, no actual cryptography
    "base64ct",
    "cms",
    "der_derive",
    "x509-cert",
];

// Target we actually build and ship for; keeps platform-only crates.
const TARGET: &str = "x86_64-unknown-linux-gnu";

// Exclude test-only workspace members which are never shipped to the bundle.
const TEST_ONLY_WORKSPACE_MEMBERS: &[&str] = &[
    "trusted-cluster-operator-tests",
    "trusted-cluster-operator-test-utils",
];

// Names of every crate reachable via a *normal* (non-dev, non-build) dependency edge from any workspace member that actually ships - i.e. what actually ends up in the built binaries.
fn normal_dependency_names() -> HashSet<String> {
    let mut args = vec![
        "tree",
        "--workspace",
        "-e",
        "normal",
        "--target",
        TARGET,
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];

    // Filtering test-only workspace members.
    for member in TEST_ONLY_WORKSPACE_MEMBERS {
        args.push("--exclude");
        args.push(member);
    }

    let output = Command::new(env!("CARGO"))
        .args(&args)
        .output()
        .expect("failed to run `cargo tree`");
    assert!(
        output.status.success(),
        "`cargo tree` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        // each line looks like "openssl v0.10.81"; we only need the name
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn cargo_metadata() -> Value {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version=1",
            &format!("--filter-platform={TARGET}"),
        ])
        .output()
        .expect("failed to run `cargo metadata`");
    assert!(
        output.status.success(),
        "`cargo metadata` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("`cargo metadata` should emit valid JSON")
}

fn as_lowercase_str_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[test]
fn no_disallowed_crypto_crates() {
    let normal_deps = normal_dependency_names();
    let metadata = cargo_metadata();

    let workspace_members: HashSet<&str> = metadata["workspace_members"]
        .as_array()
        .expect("workspace_members should be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let violations: Vec<String> = metadata["packages"]
        .as_array()
        .expect("packages should be an array")
        .iter()
        .filter(|pkg| !workspace_members.contains(pkg["id"].as_str().unwrap_or_default()))
        .filter(|pkg| normal_deps.contains(pkg["name"].as_str().unwrap_or_default()))
        .filter(|pkg| !ALLOWED_CRYPTO_CRATES.contains(&pkg["name"].as_str().unwrap_or_default()))
        .filter(|pkg| {
            let categories = as_lowercase_str_vec(&pkg["categories"]);
            let keywords = as_lowercase_str_vec(&pkg["keywords"]);
            categories.iter().any(|c| c == "cryptography")
                || keywords.iter().any(|k| k.contains("crypto"))
        })
        .map(|pkg| {
            format!(
                "{} v{}",
                pkg["name"].as_str().unwrap_or("?"),
                pkg["version"].as_str().unwrap_or("?")
            )
        })
        .collect();

    assert!(
        violations.is_empty(),
        "found crate(s) that implement their own crypto/TLS instead of a backend covered by \
         fedora-crypto-policies (https://gitlab.com/redhat-crypto/fedora-crypto-policies), among \
         *normal* (shipped) dependencies for {TARGET}: {violations:?}.\n\
         If this is a false positive, add it to ALLOWED_CRYPTO_CRATES in this test with a \
         comment explaining why. Otherwise remove the dependency, or switch to an \
         OpenSSL-backed equivalent."
    );
}
