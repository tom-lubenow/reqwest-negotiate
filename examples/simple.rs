//! Simple example demonstrating Negotiate authentication with reqwest.
//!
//! Run with: cargo run --example simple -- <url>
//!
//! Make sure you have a valid Kerberos ticket (run `kinit` first).

use reqwest_negotiate::NegotiateAuthExt;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_string());

    println!("Making request to: {}", url);

    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .negotiate_auth()?
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Headers: {:#?}", response.headers());

    let body = response.text().await?;
    println!("Body length: {} bytes", body.len());

    Ok(())
}
