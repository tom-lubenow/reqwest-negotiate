#![cfg(feature = "pure-rust")]

// Synthetic tickets and keys only. Exercises cache loading, HTTP transport and
// real AP-REQ/AP-REP cryptography without a KDC or the developer's credentials.
use reqwest_negotiate::pure_rust::{Config, Error, NegotiateClient};
use rskrb5::{
    ccache,
    client::{AsRepSession, Principal},
    keytab::EncryptionKey,
    spnego,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, SystemTime};

fn key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: vec![42; 32],
    }
}

fn cache() -> tempfile::NamedTempFile {
    let now = std::time::UNIX_EPOCH
        + Duration::from_secs(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    let ticket = rasn_kerberos::Ticket {
        tkt_vno: 5.into(),
        realm: "EXAMPLE.TEST".try_into().unwrap(),
        sname: rasn_kerberos::PrincipalName {
            r#type: 2,
            string: vec!["HTTP".try_into().unwrap(), "127.0.0.1".try_into().unwrap()],
        },
        // The client passes the opaque ticket to the server. Our test server
        // knows the session key and only needs to decrypt the authenticator.
        enc_part: rasn_kerberos::EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0; 32].into(),
        },
    };
    let session = AsRepSession {
        client: Principal::user("EXAMPLE.TEST", "test-user"),
        service: Principal::host_based_service_in_realm("HTTP", "127.0.0.1", "EXAMPLE.TEST")
            .unwrap(),
        session_key: key(),
        ticket: rasn::der::encode(&ticket).unwrap(),
        ticket_flags: [0; 4],
        auth_time: now - Duration::from_secs(60),
        start_time: now - Duration::from_secs(60),
        end_time: now + Duration::from_secs(3600),
        renew_till: None,
        key_expiration: None,
    };
    let mut cache = ccache::CCache::new(ccache::Principal::new(
        "EXAMPLE.TEST",
        1,
        vec!["test-user".into()],
    ));
    cache
        .credentials_mut()
        .push(session.to_ccache_credential().unwrap());
    let file = tempfile::NamedTempFile::new().unwrap();
    cache.save(file.path()).unwrap();
    file
}

async fn exchange(mode: &'static str) -> Result<reqwest::Response, Error> {
    let cache = cache();
    let config = Config::parse("[libdefaults]\n default_realm = EXAMPLE.TEST\n").unwrap();
    let mut client =
        NegotiateClient::from_cache(config, &format!("FILE:{}", cache.path().display()))
            .unwrap()
            .with_http_builder(
                reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(5)),
            )
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 65536);
        }
        let request = String::from_utf8(request).unwrap();
        let authorization = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then_some(value.trim())
            })
            .unwrap();
        let token = spnego::parse_negotiate_header(authorization).unwrap();
        let ap_req: rasn_kerberos::ApReq =
            rasn::der::decode(&token.krb5_ap_req().unwrap()).unwrap();
        assert_eq!(ap_req.ap_options.0.as_raw_slice(), &[0x20, 0, 0, 0]);
        let plaintext = rskrb5::crypto::AesSha1Etype::Aes256
            .decrypt_message(&key().value, ap_req.authenticator.cipher.as_ref(), 11)
            .unwrap();
        let authenticator: rasn_kerberos::Authenticator = rasn::der::decode(&plaintext).unwrap();
        let part = rasn_kerberos::EncApRepPart {
            ctime: authenticator.ctime,
            cusec: authenticator.cusec,
            subkey: None,
            seq_number: None,
        };
        let reply_key = if mode == "forged" {
            EncryptionKey {
                etype: 18,
                value: vec![7; 32],
            }
        } else {
            key()
        };
        let ap_rep = rskrb5::ap_rep::encode_build_ap_rep(&part, &reply_key, None).unwrap();
        let mut response = spnego::NegTokenResp::accept_completed()
            .with_response_token(spnego::Krb5MechToken::ap_rep(ap_rep).encode().unwrap());
        if mode == "continue" {
            response.neg_state = Some(spnego::NegState::AcceptIncomplete);
        }
        let header = spnego::negotiate_header(&spnego::SpnegoToken::Resp(response)).unwrap();
        let status = if mode == "redirect" {
            "302 Found"
        } else {
            "200 OK"
        };
        let auth_header = if mode == "missing" {
            String::new()
        } else {
            format!("WWW-Authenticate: {header}\r\n")
        };
        write!(stream, "HTTP/1.1 {status}\r\n{auth_header}Location: http://{address}/redirected\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
    });
    let result = client
        .send(reqwest::Client::new().get(format!("http://{address}/")))
        .await;
    server.join().unwrap();
    result
}

#[tokio::test]
async fn cached_service_ticket_authenticates_and_verifies_server() {
    assert_eq!(exchange("valid").await.unwrap().text().await.unwrap(), "ok");
}

#[tokio::test]
async fn forged_missing_and_incomplete_responses_fail() {
    assert!(matches!(exchange("forged").await, Err(Error::Spnego(_))));
    assert!(matches!(
        exchange("missing").await,
        Err(Error::MissingMutualAuth)
    ));
    assert!(matches!(
        exchange("continue").await,
        Err(Error::UnsupportedNegotiation)
    ));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    assert_eq!(
        exchange("redirect").await.unwrap().status(),
        reqwest::StatusCode::FOUND
    );
}

/// Run against an actual kinit cache and Negotiate endpoint supplied by the user.
#[tokio::test]
#[ignore = "requires KRB5CCNAME, Kerberos configuration and NEGOTIATE_TEST_URL"]
async fn live_kinit_cache() {
    let url = std::env::var("NEGOTIATE_TEST_URL").expect("NEGOTIATE_TEST_URL");
    let mut client = NegotiateClient::from_default_cache().unwrap();
    let response = client.send(reqwest::Client::new().get(url)).await.unwrap();
    assert!(response.status().is_success());
}
