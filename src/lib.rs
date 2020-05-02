
extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

pub mod common;

use std::fs;
use std::sync::{Arc, Mutex};
use crate::common::{Entry, Index, Key};
use std::collections::{HashMap, hash_map::RandomState};
type gs = Arc<Mutex<HashMap<Key, String>>>;
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

pub fn run_keygen(my_map: HashMap<String, String>) {
    //let shared_hm: Arc<Mutex<HashMap<Key, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let shared_hm: Arc<Mutex<HashMap<Key, String>>> = Arc::new(Mutex::new(my_map));
    manager(&shared_hm);
    let mut handles = vec![];
    for i in 1..4 {
        let hm = Arc::clone(&shared_hm);
        let handle = thread::spawn(move || {
            keygen(char::from_digit(i, 10).unwrap(), &hm);
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
    handles = vec![];
    for i in 1..4 {
        let hm = Arc::clone(&shared_hm);
        let handle = thread::spawn(move || {
            pubkey_or_sign(char::from_digit(i, 10).unwrap(), false, &hm);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
    info!("finished.");
    
}
    /*
    let matches = App::new("TSS CLI Utility")
        .version("0.1.0")
        .author("Kaspars Sprogis <darklow@gmail.com>")
//        .about("")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommands(vec![
            SubCommand::with_name("manager").about("Run state manager"),
            SubCommand::with_name("keygen").about("Run keygen")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Target keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager. E.g. http://127.0.0.2:8002")),
            SubCommand::with_name("pubkey").about("Get X,Y of a pub key")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path (Optional)")),
            SubCommand::with_name("sign").about("Run signer")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("message")
                    .index(3)
                    .required(true)
                    .takes_value(true)
                    .help("Message to sign in hex format"))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path"))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager"))
        ])
        .get_matches();
    */
//    match matches.subcommand() {
        //("pubkey", Some(sub_matches)) | ("sign", Some(sub_matches)) => {
pub fn pubkey_or_sign(party: char, pub_or_sign: bool, shm: &gs) {
    let mut keysfile_path = String::from("keysfile_");
    keysfile_path.push(party);

    // Read data from keys file
    let data = fs::read_to_string(&keysfile_path).expect(
        format!("Unable to load keys file at location: {}", &keysfile_path).as_str(),
    );
    let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    // Get root pub key or HD pub key at specified path
    //let path = sub_matches.value_of("path").unwrap_or("");
    let path = "";
    let (f_l_new, y_sum) = match path.is_empty() {
        true => (ECScalar::zero(), y_sum),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| s.trim().parse::<BigInt>().unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());
            (f_l_new, y_sum_child.clone())
        }
    };

    // Return pub key as x,y
    if pub_or_sign {
        let ret_dict = json!({
            "x": &y_sum.x_coor(),
            "y": &y_sum.y_coor(),
            "path": path,
        });
        info!("{}", ret_dict.to_string());
    } else {
        // Parse message to sign
        let message_str = "PolySign";
        let message = match hex::decode(message_str) {
            Ok(x) => x,
            Err(_e) => message_str.as_bytes().to_vec(),
        };
        let message = &message[..];
        let manager_addr = party.to_string();
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
            manager_addr,
            party_keys,
            shared_keys,
            party_id,
            &mut vss_scheme_vec,
            paillier_key_vector,
            &y_sum,
            &params,
            &message,
            &f_l_new,
            false,
            shm,
            // !path.is_empty(), 
        )
    }
}

pub fn manager(shm: &gs) {
//("manager", Some(_matches)) => manager::run_manager(),
    manager::run_manager(shm);
}
pub fn keygen(party: char, shm: &gs) {
//("keygen", Some(sub_matches)) => {
    let addr = String::from("dummy");
    /*    let addr = sub_matches
        .value_of("manager_addr")
        .unwrap_or("http://127.0.0.1:8001")
        .to_string();
    */

    let mut keysfile_path = String::from("keysfile_");
    keysfile_path.push(party);
    //let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();
    /*let params = Params {
        threshold: String::from("2"),
        parties: String::from("3"),
    };*/
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
        &keysfile_path,
        &params,
        shm
    );
}