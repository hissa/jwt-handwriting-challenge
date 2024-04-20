use std::collections::HashMap;

fn main() {
    println!("Hello, world!");
    println!("{}", base64("ABCDEFG".as_bytes()));
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
        splitted.push((first_byte << 4 | second_byte >> 4) & 0b_0011_1111);

        if let None = bytes.get(chunk * 3 + 1) {
            continue;
        }

        let third_byte = match bytes.get(chunk * 3 + 2) {
            Some(b) => b,
            None => &0x00,
        };
        splitted.push((second_byte << 2 | third_byte >> 6) & 0b_0011_1111);

        if let None = bytes.get(chunk * 3 + 2) {
            continue;
        }

        splitted.push(third_byte & 0b0011_1111);
    }

    splitted
}
