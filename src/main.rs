use std::collections::HashMap;

use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::SigningKey,
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey, RsaPublicKey,
};

fn main() {
    let private_key = prepare_keys();
    println!("{}", create_jwt(private_key));
}

fn create_jwt(private_key: RsaPrivateKey) -> String {
    let header = r#"{"alg":"RS256"}"#;
    let payload = r#"{"iat":1713627229}"#;

    let header = base64_url(header.as_bytes());
    let payload = base64_url(payload.as_bytes());

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut rng = rand::thread_rng();
    let body = [header, payload].join(".");
    let signature = signing_key.sign_with_rng(&mut rng, body.as_bytes());
    let signature = base64_url(&signature.to_bytes());

    [body, signature.to_string()].join(".")
}

fn prepare_keys() -> RsaPrivateKey {
    match RsaPrivateKey::read_pkcs1_pem_file("id_rsa") {
        Ok(pk) => pk,
        Err(_) => generate_keys().0,
    }
}

fn generate_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    priv_key
        .write_pkcs1_pem_file("id_rsa", rsa::pkcs1::LineEnding::LF)
        .expect("Failed to write private key");

    pub_key
        .write_pkcs1_pem_file("id_rsa.pub", rsa::pkcs1::LineEnding::LF)
        .expect("Failed to write public key");

    (priv_key, pub_key)
}

fn base64_url(bytes: &[u8]) -> String {
    base64(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "")
}

fn base64(bytes: &[u8]) -> String {
    let splitted = split_6bit(bytes);
    let table = base64_table();
    let replaced = splitted.iter().map(|b| table[b]);
    let padding = (0..replaced.len() % 4).map(|_| '=');

    replaced.chain(padding).collect()
}

fn base64_table() -> HashMap<u8, char> {
    let upper_part = ('A'..='Z').map(|c| (c as u8 - b'A', c));
    let lower_part = ('a'..='z').map(|c| (c as u8 - b'a' + 26, c));
    let numeral_part = ('0'..='9').map(|c| (c as u8 - b'0' + 52, c));
    let sign_part = [(62 as u8, '+'), (63 as u8, '/')].into_iter();

    HashMap::from_iter(
        upper_part
            .chain(lower_part)
            .chain(numeral_part)
            .chain(sign_part),
    )
}

fn split_6bit(bytes: &[u8]) -> Vec<u8> {
    static SIX_BIT_MASK: u8 = 0b_0011_1111;

    let bytes = bytes.to_vec();
    let chunk_length = match bytes.len() % 3 {
        0 => bytes.len() / 3,
        _ => bytes.len() / 3 + 1,
    };

    let mut splitted = Vec::<u8>::new();
    for chunk in 0..chunk_length {
        let first_byte = bytes.get(chunk * 3).expect("Empty chunk is given.");
        splitted.push(first_byte >> 2);

        let second_byte = match bytes.get(chunk * 3 + 1) {
            Some(b) => b,
            None => &0x00,
        };
        splitted.push((first_byte << 4 | second_byte >> 4) & SIX_BIT_MASK);

        if let None = bytes.get(chunk * 3 + 1) {
            continue;
        }

        let third_byte = match bytes.get(chunk * 3 + 2) {
            Some(b) => b,
            None => &0x00,
        };
        splitted.push((second_byte << 2 | third_byte >> 6) & SIX_BIT_MASK);

        if let None = bytes.get(chunk * 3 + 2) {
            continue;
        }

        splitted.push(third_byte & SIX_BIT_MASK);
    }

    splitted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_6bit() {
        let bytes = vec![0b_1101_1010, 0b_1010_1101, 0b_0110_1010];
        let expected = vec![0b_0011_0110, 0b_0010_1010, 0b_0011_0101, 0b_0010_1010];
        assert_eq!(split_6bit(&bytes), expected);
    }

    #[test]
    fn test_base64_table() {
        let table = base64_table();
        assert_eq!(table.get(&0), Some(&'A'));
        assert_eq!(table.get(&25), Some(&'Z'));
        assert_eq!(table.get(&26), Some(&'a'));
        assert_eq!(table.get(&51), Some(&'z'));
        assert_eq!(table.get(&52), Some(&'0'));
        assert_eq!(table.get(&61), Some(&'9'));
        assert_eq!(table.get(&62), Some(&'+'));
        assert_eq!(table.get(&63), Some(&'/'));
    }

    #[test]
    fn test_base64() {
        let bytes = "ABCDEFG".as_bytes();
        assert_eq!(base64(bytes), "QUJDREVGRw==");
    }

    #[test]
    fn test_base64_url() {
        let bytes = vec![0b_1111_1011, 0b_1111_0000, 0b_0000_0000];
        assert_eq!(base64_url(&bytes), "-_AA");
    }
}
