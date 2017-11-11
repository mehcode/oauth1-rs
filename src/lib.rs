extern crate base64;
extern crate rand;
extern crate ring;
extern crate time;
extern crate url;

use std::borrow::Cow;
use std::collections::HashMap;
use rand::Rng;
use url::percent_encoding;
use ring::{digest, hmac};

#[derive(Clone, Debug)]
pub struct Token<'a> {
    pub key: Cow<'a, str>,
    pub secret: Cow<'a, str>,
}

impl<'a> Token<'a> {
    pub fn new<K, S>(key: K, secret: S) -> Self
    where
        K: Into<Cow<'a, str>>,
        S: Into<Cow<'a, str>>,
    {
        Token {
            key: key.into(),
            secret: secret.into(),
        }
    }
}

pub fn authorize(
    method: &str,
    uri: &str,
    consumer: &Token,
    token: Option<&Token>,
    params: Option<HashMap<&str, Cow<str>>>,
) -> String {
    let mut params = params.unwrap_or_else(HashMap::new);
    let timestamp = time::now_utc().to_timespec().sec.to_string();
    let nonce: String = rand::thread_rng().gen_ascii_chars().take(32).collect();

    params.insert("oauth_consumer_key", consumer.key.clone().into());
    params.insert("oauth_nonce", nonce.into());
    params.insert("oauth_signature_method", "HMAC-SHA1".into());
    params.insert("oauth_timestamp", timestamp.into());
    params.insert("oauth_version", "1.0".into());
    if let Some(tk) = token {
        params.insert("oauth_token", tk.key.as_ref().into());
    }

    let signature = gen_signature(
        method,
        uri,
        &to_query(&params),
        &consumer.secret,
        token.map(|t| t.secret.as_ref()),
    );

    params.insert("oauth_signature", signature.into());

    let mut pairs = params
        .iter()
        .filter(|&(k, _)| k.starts_with("oauth_"))
        .map(|(k, v)| format!("{}=\"{}\"", k, encode(v)))
        .collect::<Vec<_>>();

    pairs.sort();

    format!("OAuth {}", pairs.join(", "))
}

#[derive(Copy, Clone)]
struct StrictEncodeSet;

// Encode all but the unreserved characters defined in
// RFC 3986, section 2.3. "Unreserved Characters"
// https://tools.ietf.org/html/rfc3986#page-12
//
// This is required by
// OAuth Core 1.0, section 5.1. "Parameter Encoding"
// https://oauth.net/core/1.0/#encoding_parameters
impl percent_encoding::EncodeSet for StrictEncodeSet {
    #[inline]
    fn contains(&self, byte: u8) -> bool {
        !((byte >= 0x61 && byte <= 0x7a) || // A-Z
          (byte >= 0x41 && byte <= 0x5a) || // a-z
          (byte >= 0x30 && byte <= 0x39) || // 0-9
          (byte == 0x2d) || // -
          (byte == 0x2e) || // .
          (byte == 0x5f) || // _
          (byte == 0x7e)) // ~
    }
}

fn encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), StrictEncodeSet).collect()
}

fn to_query(params: &HashMap<&str, Cow<str>>) -> String {
    let mut pairs: Vec<_> = params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect();

    pairs.sort();
    pairs.join("&")
}

fn gen_signature(
    method: &str,
    uri: &str,
    query: &str,
    consumer_secret: &str,
    token_secret: Option<&str>,
) -> String {
    let base = format!("{}&{}&{}", encode(method), encode(uri), encode(query));

    let key = format!(
        "{}&{}",
        encode(consumer_secret),
        encode(token_secret.unwrap_or(""))
    );

    let s_key = hmac::SigningKey::new(&digest::SHA1, key.as_ref());
    let signature = hmac::sign(&s_key, base.as_bytes());

    base64::encode(signature.as_ref())
}
