use std::{fmt::Write, iter};

use dialoguer::Input;
use lab4helper::hashlib::Hash;

pub const UID_KEY_PAIRS: [&str; 5] = [
    "1001:123456",
    "1002:983abe",
    "1003:793zye",
    "1004:88zjxc",
    "1005:xciujk",
];
pub const SERVER_URL: &str = "http://www.seedlab-hashlen.com/";

pub const NAME_ARG: &str = "myname";
pub const UID_ARG: &str = "uid";
pub const LST_ARG: &str = "lstcmd=1";
pub const DOWNLOAD_ARG: &str = "download=secret.txt";
pub const MAC_ARG: &str = "mac";

pub const SECRET_FILE: &str = "secret.txt";

fn main() {
    println!("Options:");
    println!("1: Lab Part 1 (url generation");
    println!("2: Lab Part 2 (padded message generation)");
    println!("3: Lab Part 3 (hash length extension attack)");

    let selection = loop {
        match Input::<usize>::new()
            .with_prompt("What do you want to do? (Enter a value between 0-2)")
            .interact_text()
        {
            Ok(val) => {
                if !(1..=3).contains(&val) {
                    continue;
                }
                break val;
            }
            Err(err) => {
                println!("Invalid input. Error: {err}");
                continue;
            }
        }
    };

    match selection {
        1 => {
            url_generator();
        }
        2 => {
            padding_generator();
        }
        3 => {
            hash_length_extension();
        }
        _ => {
            unreachable!()
        }
    }
}

fn hash_length_extension() {
    let name: String = loop {
        match Input::<String>::new()
            .with_prompt("Enter the name to use (No Spaces)")
            .allow_empty(false)
            .interact_text()
        {
            Ok(val) => {
                let trimmed: &str = val.trim();
                break trimmed.to_string();
            }
            Err(err) => {
                println!("Invalid Input. Error: {err}");
                continue;
            }
        };
    };
    for (i, uid_key) in UID_KEY_PAIRS.iter().enumerate().skip(1) {
        println!("{i}: {uid}", uid = uid_key.split_once(":").unwrap().0);
    }
    let id_index: usize = loop {
        match Input::new()
            .with_prompt("Select your UID (Enter a value between 1-4)")
            .interact_text()
        {
            Ok(val) => {
                if !(1..=4).contains(&val) {
                    continue;
                }
                break val;
            }
            Err(err) => {
                println!("Invalid Input. Error:{err}");
                continue;
            }
        }
    };

    let mut url_result = String::new();

    url_result.push_str(SERVER_URL);

    url_result.push('?');

    url_result.push_str(NAME_ARG);

    url_result.push('=');

    url_result.push_str(&name);

    url_result.push('&');

    url_result.push_str(UID_ARG);

    url_result.push('=');

    let (uid, key) = UID_KEY_PAIRS[id_index].split_once(":").unwrap();

    url_result.push_str(uid);

    url_result.push('&');
    url_result.push_str(LST_ARG);

    let mut mac_string = String::from(key);
    mac_string.push(':');

    let (_, command) = url_result.split_once("?").unwrap();
    mac_string.push_str(command);
    println!("{mac_string}");

    let mut hash_builder = Hash::new();

    hash_builder.update(mac_string.as_bytes());
    let hash = hash_builder.finalize();

    let mut hash_string = String::with_capacity(hash.len() * 2);

    for byte in hash {
        write!(&mut hash_string, "{byte:02x}").unwrap();
    }

    let length_in_bits = mac_string.len() as u64 * 8;

    let mut padding_bytes = Vec::new();

    padding_bytes.push(0x80);

    let k = (55 - mac_string.len() % 64) % 64;

    padding_bytes.extend(iter::repeat_n(0, k));
    padding_bytes.extend(length_in_bits.to_be_bytes());

    for byte in &padding_bytes {
        url_result.push_str(&format!("%{byte:02x}"));
    }

    let original_padded_length = mac_string.len() + padding_bytes.len();

    let mut new_mac_builder = Hash::new_with_state(hash, original_padded_length);
    new_mac_builder.update(format!("&{}", DOWNLOAD_ARG));
    let new_hash = new_mac_builder.finalize();

    let mut new_hash_string = String::with_capacity(hash.len() * 2);

    for byte in new_hash {
        write!(&mut new_hash_string, "{byte:02x}").unwrap();
    }

    url_result.push('&');
    url_result.push_str(DOWNLOAD_ARG);

    url_result.push('&');

    url_result.push_str(MAC_ARG);

    url_result.push('=');
    url_result.push_str(&new_hash_string);

    println!("Hash length extension attack URL: {url_result}");
}
fn url_generator() {
    let name: String = loop {
        match Input::<String>::new()
            .with_prompt("Enter the name to use (No Spaces)")
            .allow_empty(false)
            .interact_text()
        {
            Ok(val) => {
                let trimmed: &str = val.trim();
                break trimmed.to_string();
            }
            Err(err) => {
                println!("Invalid Input. Error: {err}");
                continue;
            }
        };
    };

    for (i, uid_key) in UID_KEY_PAIRS.iter().enumerate().skip(1) {
        println!("{i}: {uid_key}");
    }
    let id_index: usize = loop {
        match Input::new()
            .with_prompt("Select your UID:Key pair (Enter a value between 1-4)")
            .interact_text()
        {
            Ok(val) => {
                if !(1..=4).contains(&val) {
                    continue;
                }
                break val;
            }
            Err(err) => {
                println!("Invalid Input. Error:{err}");
                continue;
            }
        }
    };

    let list_cmd = loop {
        match Input::<String>::new()
            .with_prompt("Issue list command? (Enter 'y' or 'n')")
            .interact_text()
        {
            Ok(val) => match val.to_ascii_lowercase().trim() {
                "y" | "yes" | "1" => {
                    break true;
                }
                "n" | "no" | "0" => {
                    break false;
                }
                _ => {
                    println!("Invalid Input");
                    continue;
                }
            },
            Err(err) => {
                println!("Invalid Input. Error: {err}")
            }
        }
    };

    let download_cmd = loop {
        match Input::<String>::new()
            .with_prompt("Issue download command for secret.txt? (Enter 'y' or 'n')")
            .interact_text()
        {
            Ok(val) => match val.to_ascii_lowercase().trim() {
                "y" | "yes" | "1" => {
                    break true;
                }
                "n" | "no" | "0" => {
                    break false;
                }
                _ => {
                    println!("Invalid Input");
                    continue;
                }
            },
            Err(err) => {
                println!("Invalid Input. Error: {err}")
            }
        }
    };

    URLBuilder::new(&name, id_index)
        .list_cmd(list_cmd)
        .download_cmd(download_cmd)
        .print();
}

fn padding_generator() {
    let message = loop {
        match Input::<String>::new()
            .with_prompt("Enter a message to pad")
            .interact_text()
        {
            Ok(val) => {
                let trimmed = val.trim();
                if trimmed.len() + 1 + 8 > 64 {
                    println!("Message is too long");
                    continue;
                }
                break trimmed.to_string();
            }
            Err(err) => {
                println!("Invalid input. Error: {err}");
                continue;
            }
        }
    };

    let length_in_bits = message.len() as u64 * 8;

    let zero_padding_count = 64 - message.len() - 1 - 8;

    let mut padded_bytes = Vec::new();

    padded_bytes.extend(message.as_bytes());

    padded_bytes.push(0x80);

    padded_bytes.extend(iter::repeat_n(0, zero_padding_count));

    padded_bytes.extend(length_in_bits.to_be_bytes());

    assert!(padded_bytes.len() == 64);

    let mut output_string = String::new();

    for byte in padded_bytes {
        write!(&mut output_string, "{byte:02x} ").unwrap();
    }

    println!("{output_string}");
}

pub struct URLBuilder {
    name: String,
    id_index: usize,
    list_cmd: bool,
    download_cmd: bool,
}

impl URLBuilder {
    pub fn new(name: &str, id_index: usize) -> Self {
        Self {
            name: name.to_string(),
            id_index,
            list_cmd: false,
            download_cmd: false,
        }
    }
    pub fn list_cmd(self, value: bool) -> Self {
        Self {
            list_cmd: value,
            ..self
        }
    }
    pub fn download_cmd(self, value: bool) -> Self {
        Self {
            download_cmd: value,
            ..self
        }
    }
    pub fn print(self) {
        let mut url_result = String::new();

        url_result.push_str(SERVER_URL);

        url_result.push('?');

        url_result.push_str(NAME_ARG);

        url_result.push('=');

        url_result.push_str(&self.name);

        url_result.push('&');

        url_result.push_str(UID_ARG);

        url_result.push('=');

        let (uid, key) = UID_KEY_PAIRS[self.id_index].split_once(":").unwrap();

        url_result.push_str(uid);

        if self.list_cmd {
            url_result.push('&');
            url_result.push_str(LST_ARG);
        }

        if self.download_cmd {
            url_result.push('&');
            url_result.push_str(DOWNLOAD_ARG);
        }

        let mut mac_string = String::from(key);
        mac_string.push(':');

        let (_, command) = url_result.split_once("?").unwrap();
        mac_string.push_str(command);

        let hash = Hash::hash(mac_string.as_bytes());

        let mut hash_string = String::with_capacity(hash.len() * 2);

        for byte in hash {
            write!(&mut hash_string, "{byte:02x}").unwrap();
        }
        url_result.push('&');
        url_result.push_str(MAC_ARG);
        url_result.push('=');
        url_result.push_str(&hash_string);

        println!();
        println!("URL Result: {url_result}");
        println!();

        println!("Mac String Result: {mac_string}");

        println!();
        println!("Hash Hex String: {hash_string }");
    }
}
