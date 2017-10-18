# OAuth1
> Basic OAuth1 library for Rust.

## Usage

```rust
extern crate oauth1;
extern crate reqwest;

pub fn main() {
    let url = "https://api.twitter.com/1.1/account/verify_credentials.json";
    let res = client.get(url)
        .header(Authorization(oauth1::authorize(
            "GET",
            url,
            Token::new("consumer_key", "consumer_secret"),
            Some(Token::new("auth_token", "auth_token_secret")),
            None,
        )))
        .send().unwrap();
}
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
