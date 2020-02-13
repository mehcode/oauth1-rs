use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use rand::distributions::{Alphanumeric, Distribution};
use rand::thread_rng;
use ring::hmac::{self, HMAC_SHA1_FOR_LEGACY_USE_ONLY};
use std::borrow::Cow;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
    params: Option<&[(&str, &str)]>,
    realm: Option<&str>
) -> String {
    let timestamp = time::OffsetDateTime::now().timestamp().to_string();

    let nonce: String = Alphanumeric.sample_iter(thread_rng()).take(32).collect();

    let mut parameters: Vec<(&str, &str)> = vec![
    ("oauth_consumer_key", &consumer.key),
    ("oauth_nonce", &nonce),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", &timestamp),
    ("oauth_version", "1.0")];
    if let Some(tk) = token {
        parameters.push(("oauth_token", &tk.key));
    }

    let mut signature_params = parameters.clone();
    if let Some(unwrapped_params) = params{
    signature_params.extend(unwrapped_params);
    }
    let signature = gen_signature(
        method,
        uri,
        &to_query(&signature_params),
        &consumer.secret,
        token.map(|t| t.secret.as_ref()),
    );

    parameters.push(("oauth_signature", &signature));
    if let Some(unwrapped_realm) = realm {
        parameters.push(("realm", unwrapped_realm));
    }

    let mut pairs = parameters
        .iter()
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
static STRICT_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), &STRICT_ENCODE_SET).collect()
}

fn to_query(params: &[(&str, &str)]) -> String {
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

    let s_key = hmac::Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_ref());
    let signature = hmac::sign(&s_key, base.as_bytes());

    base64::encode(signature.as_ref())
}
