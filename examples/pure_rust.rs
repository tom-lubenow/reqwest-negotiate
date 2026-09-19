use reqwest_negotiate::pure_rust::NegotiateClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).expect("usage: pure_rust URL");
    let mut auth = NegotiateClient::from_default_cache()?;
    let response = auth.send(reqwest::Client::new().get(url)).await?;
    println!("{}", response.status());
    println!("{}", response.text().await?);
    Ok(())
}
