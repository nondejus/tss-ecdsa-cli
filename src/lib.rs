//extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
//extern crate reqwest;
extern crate serde_json;

pub mod common;
pub mod random_state;
pub mod error;

use std::fs;
use std::sync::{Arc, Mutex};
use crate::common::{Entry, Index, Key};
use std::collections::{HashMap};
type gs = HashMap<Key, String, random_state::PsRandomState>;
//use clap::{App, AppSettings, Arg, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use serde_json::json;

use common::{hd_keys, keygen, manager, signer, Params};
use log::{info};
use std::thread;
use std::char;
use random_state::PsRandomState;
use crate::common::keygen::KeyGenResult;
pub fn run_keygen() {
    //let shared_hm: Arc<Mutex<HashMap<Key, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut shared_hm: HashMap<Key, String, PsRandomState> = HashMap::with_hasher(PsRandomState::new());
    manager(&mut shared_hm);

    
    let keygen_result = keygen(char::from_digit(1, 10).unwrap(), &mut shared_hm);
    pubkey_or_sign(false, keygen_result, &mut shared_hm);
    info!("finished.");
    
}
pub fn pubkey_or_sign(pub_or_sign: bool, keygen_result: Vec<KeyGenResult>, shm: &mut gs) {
    //let mut keysfile_path = String::from("keysfile_");
    //keysfile_path.push(party);

    // Read data from keys file
    //let data = fs::read_to_string(&keysfile_path).expect(
    //    format!("Unable to load keys file at location: {}", &keysfile_path).as_str(),
    //);
        /*let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS>,
            Vec<EncryptionKey>,
            GE,
        ) = serde_json::from_str(&data).unwrap();
        */

        // Get root pub key or HD pub key at specified path
        //let path = sub_matches.value_of("path").unwrap_or("");
    let path = "";
    /*let (f_l_new, y_sum) = match path.is_empty() {
        true => (ECScalar::zero(), y_sum),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| s.trim().parse::<BigInt>().unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());
            (f_l_new, y_sum_child.clone())
        }
    };*/
    // Return pub key as x,y
    if pub_or_sign {

        for n in 0..3 {
            let ret_dict = json!({
                "x": &keygen_result[n].y_sum.x_coor(),
                "y": &keygen_result[n].y_sum.y_coor(),
                "path": path,
            });
            info!("{}", ret_dict.to_string());
        }
    } else {
        // Parse message to sign
        let message_str = "PolySign";
        let message = match hex::decode(message_str) {
            Ok(x) => x,
            Err(_e) => message_str.as_bytes().to_vec(),
        };
        let message = &message[..];
        //let manager_addr = party.to_string();
        /*let manager_addr = sub_matches
            .value_of("manager_addr")
            .unwrap_or("http://127.0.0.1:8001")
            .to_string();
        */
        // Parse threshold params
        /*let params: Vec<&str> = sub_matches
            .value_of("params")
            .unwrap_or("")
            .split("/")
            .collect();
        */
        //            info!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
        let params = Params {
            threshold: String::from("2"),
            parties: String::from("3"),
        };
        signer::sign(
            keygen_result, 
            &params,
            &message,
            &ECScalar::zero(),
            false,
            shm,
            // !path.is_empty(), 
        );
    }
    
}

pub fn manager(shm: &mut gs) {
//("manager", Some(_matches)) => manager::run_manager(),
    manager::run_manager(shm);
}
pub fn keygen(party: char, shm: &mut gs) -> Vec<KeyGenResult> {
//("keygen", Some(sub_matches)) => {
    let addr = String::from("dummy");
    /*    let addr = sub_matches
        .value_of("manager_addr")
        .unwrap_or("http://127.0.0.1:8001")
        .to_string();
    */

    //let mut keysfile_path = String::from("keysfile_");
    //keysfile_path.push(party);
    //let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();

    let params = vec!["2", "3"];
    /*
    let params: Vec<&str> = sub_matches
        .value_of("params")
        .unwrap_or("")
        .split("/")
        .collect();
    */
    keygen::run_keygen(
        &addr,
        &String::from("dummy_keys_file"),
        &params,
        shm
    )
}