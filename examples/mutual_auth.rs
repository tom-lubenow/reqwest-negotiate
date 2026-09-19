use reqwest_negotiate::NegotiateAuthExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).expect("usage: mutual_auth URL");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let (request, mut context) = client.get(url).negotiate_auth_mutual()?;
    let response = request.send().await?;
    context.verify_response(&response)?;
    println!("{}", response.status());
    println!("{}", response.text().await?);
    Ok(())
}
