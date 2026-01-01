//! Example demonstrating mutual authentication with Negotiate.
//!
//! Run with: cargo run --example mutual_auth -- <url>
//!
//! This example verifies the server's identity in addition to authenticating the client.
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

    // Get the request builder and the authentication context
    let (builder, mut ctx) = client.get(&url).negotiate_auth_mutual()?;

    // Send the request
    let response = builder.send().await?;

    println!("Status: {}", response.status());

    // Verify the server's identity
    match ctx.verify_response(&response) {
        Ok(()) => println!("✓ Server identity verified (mutual auth complete)"),
        Err(e) => println!("✗ Server verification failed: {}", e),
    }

    println!("Context complete: {}", ctx.is_complete());

    let body = response.text().await?;
    println!("Body length: {} bytes", body.len());

    Ok(())
}
