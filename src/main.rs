#![allow(non_snake_case)]
//#![feature(proc_macro_hygiene, decl_macro)]
/*
extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

use std::fs;
use std::sync::{Arc, Mutex};
use crate::common::{Entry, Index, Key};
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
mod common;
use std::thread;
use std::char;
*/
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use env_logger;


use tss_cli::run_keygen;

fn main() {

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    env_logger::init();

    run_keygen();
}