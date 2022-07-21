mod utils;

use std::error::Error;
use core::result::Result;

use wasm_bindgen::prelude::*;
use ed25519_dalek::{ed25519, ExpandedSecretKey, PublicKey, SignatureError, Signature, Verifier,  SecretKey};
use {
    ruc::*,
    base64,
};
use hex;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn sign(public_key: &str, secret_key:&str, message: &str) ->  Result<String, JsValue>{

    let decode = base64::decode_config(public_key, base64::URL_SAFE).unwrap();//from_hex(&form.anonymous_address).unwrap();
    match  PublicKey::from_bytes(&decode)
    {
        Ok(public_key) => {
            let decode = base64::decode_config(secret_key, base64::URL_SAFE).unwrap();
            let secret_key = SecretKey::from_bytes(&decode).unwrap();
            let end_key = ExpandedSecretKey::from(&secret_key);
            let sign = end_key.sign(message.as_bytes(), &public_key);
            return  Ok(hex::encode(sign));
        },
        Err(e) => {
             return Err(JsValue::from_str(&e.to_string()));
        }
    }
}
