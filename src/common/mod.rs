pub mod hd_keys;
pub mod keygen;
pub mod manager;
pub mod signer;

use std::sync::{Arc, Mutex};

use std::collections::HashMap;
type gs = Arc<Mutex<HashMap<Key, String, crate::random_state::PsRandomState>>>;

use std::{iter::repeat, thread, time, time::Duration};
use log::info;
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize::KeySize256,
    aes_gcm::AesGcm,
};
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
    let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
    gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
    AEAD {
        ciphertext: out.to_vec(),
        tag: out_tag.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
    out
}
/*
pub fn postb<T>(
    addr: &String,
    //client: &Client,
    path: &str,
    body: T,
    shm: &gs) -> Option<String>
{
    //    let mut addr = env::args()
    //        .nth(4)
    //        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
    //    for argument in env::args() {
    //        if argument.contains("://") {
    //            let addr_parts: Vec<&str> = argument.split("http:").collect();
    //            addr = format!("http:{}", addr_parts[1]);
    //        }
    //    }
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..retries {
        let addr = format!("{}/{}", addr, path);
        match path {
            "get" => {
                manager::get(, shm);
            },
            "set" => { return None},
            "signupkeygen" => {return None},
            "signupkeygen" => {return None},
            _ => {info!("unknown action"); },
        
        }
        //let res = client.post(&addr).json(&body).send();

        /*if let Ok(res) = res {
            return Some(res.text().unwrap());
        }*/
        thread::sleep(retry_delay);
    }
    None
}
*/
pub fn broadcast(
    addr: &String,
    //client: &Client,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
    shm: &gs
) -> Result<(), ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };
    manager::set(entry, shm)
    /*let res_body = postb(&addr,
        // &client,
         "set", entry, shm).unwrap();
    serde_json::from_str(&res_body).unwrap()
    */
}

pub fn sendp2p(
    addr: &String,
    //client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
    shm: &gs
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };
    manager::set(entry, shm)
    /*let res_body = postb(&addr, 
        //&client,
         "set", entry, shm).unwrap();
    serde_json::from_str(&res_body).unwrap()
    */
}

pub fn poll_for_broadcasts(
    addr: &String,
    //client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
    shm: &gs
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                /*let res_body = postb(&addr,
                    // &client,
                     "get", index.clone(), shm).unwrap();
                */
                let res_body = manager::get(index.clone(), shm);
                //let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = res_body {
                    ans_vec.push(answer.value);
                    info!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn poll_for_p2p(
    addr: &String,
    //client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
    shm: &gs
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                /*let res_body = postb(&addr,
                    // &client,
                     "get", index.clone(), shm).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();*/
                let res_body = manager::get(index.clone(), shm);
                if let Ok(answer) = res_body {
                    ans_vec.push(answer.value);
                    info!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_vec(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}
