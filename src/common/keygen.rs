use std::{fs, time};


use std::sync::{Arc, Mutex};
use crate::common::{Entry, Index, Key};
use std::collections::HashMap;
type gs = HashMap<Key, String, crate::random_state::PsRandomState>;
use log::info;
use crate::error::Error as MyError;



use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
//use reqwest::blocking::Client;

use crate::common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, sendp2p, Params,
    PartySignup, AEAD,
};


pub fn key_round1(input_json: String) -> Result<String, MyError> {
    use std::convert::TryFrom;
    let val: serde_json::Value = serde_json::from_str(&input_json)?;
    let mut party_num = -1; 
    if let Some(num) = val["data"]["party"].as_i64() {
        party_num = num;
    } else{
        return Err(MyError{err: "None Error in party num parsing.".to_string()})
    }
    let party_keys = Keys::create(usize::try_from(party_num).unwrap());
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();
    Ok(
        serde_json::json!({
        "round": "round1",
        "party": party_num.to_string(),
        "keygen_or_sign": "keygen",
        "party_keys": party_keys,
        "bc_i": bc_i,
        "decom_i": decom_i, 
        }).to_string()
    )
}

use crate::random_state::PsRandomState;
pub fn run_keygen(addr: &String, keysfile_path: &String, params: &Vec<&str>, shm: &mut gs) {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();
    //let client = Client::new();
    let keysfile_path_i = ["keys_party_1.json", "keys_party_2.json", "keys_party_3.json"];
    // delay:
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let part_num_int: [usize; 3] = [1, 2, 3];
    let mut uuids_i: Vec<String> = Vec::new();
    let tn_params = Params {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };
    for n in part_num_int.iter() {
        let (p, uuid) = match keygen_signup(&addr,
            // &client,
            &tn_params, shm).unwrap() {
            PartySignup { number, uuid } => (number, uuid),
        };
        info!("number: {:?}, uuid: {:?}", p, &uuid);
        uuids_i.push(uuid);
    }
    let mut party_keys = vec![];
    let mut b_d_i = vec![];
    for n in part_num_int.iter(){
        let pp = Keys::create(*n);
        let (bc_i, decom_i) = pp.phase1_broadcast_phase3_proof_of_correct_key();

        // send commitment to ephemeral public keys, get round 1 commitments of other parties
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round1",
            serde_json::to_string(&bc_i).unwrap(),
            uuids_i[n - 1].clone(),
            shm
        )
        .is_ok());
        party_keys.push(pp);
        b_d_i.push((bc_i, decom_i));
    }
    let mut bc_vec_i = vec![];
    for n in part_num_int.iter(){
        let round1_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            PARTIES,
            delay,
            "round1",
            uuids_i[*n - 1].clone(),
            shm
        );

        let mut bc1_vec = round1_ans_vec
            .iter()
            .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
            .collect::<Vec<_>>();

        bc1_vec.insert(*n as usize - 1, b_d_i[*n - 1].0.clone());

        // send ephemeral public keys and check commitments correctness
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round2",
            serde_json::to_string(&(b_d_i[*n - 1].1)).unwrap(),
            uuids_i[*n -1].clone(),
            shm
        )
        .is_ok());
        bc_vec_i.push(bc1_vec);
    }

////////////////////////////////////////////////////////////////////
    let mut round2_ans_vec_i = vec![];
    for n in part_num_int.iter(){
        let round2_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            PARTIES,
            delay,
            "round2",
            uuids_i[*n-1].clone(),
            shm,
        );
        round2_ans_vec_i.push(round2_ans_vec);
    }
    let mut point_vec_i = vec![];
    let mut decom_vec_i = vec![];
    let mut enc_keys_i = vec![];
    let mut vss_scheme_i = vec![];
    let mut secret_shares_i = vec![];
    let mut y_sum_i = vec![];
    for n in part_num_int.iter(){
        let mut j = 0;
        let mut point_vec: Vec<GE> = Vec::new();
        let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
        let mut enc_keys: Vec<BigInt> = Vec::new();
        for i in 1..=PARTIES {
            if i == *n as u16 {
                let decom_i = b_d_i[*n - 1].1.clone();
                point_vec.push(decom_i.y_i);
                decom_vec.push(decom_i.clone());
            } else {
                let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec_i[*n-1][j]).unwrap();
                point_vec.push(decom_j.y_i);
                decom_vec.push(decom_j.clone());
                enc_keys.push((decom_j.y_i.clone() * party_keys[*n - 1].u_i).x_coor().unwrap());
                j = j + 1;
            }
        }

        let (head, tail) = point_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);
        y_sum_i.push(y_sum);
        let (vss_scheme, secret_shares, _index) = party_keys[*n - 1]
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &params, &decom_vec, &(bc_vec_i[*n-1]),
            )
            .expect("invalid key");

        //////////////////////////////////////////////////////////////////////////////

        let mut j = 0;
        for (k, i) in (1..=PARTIES).enumerate() {
            if i != *n as u16 {
                // prepare encrypted ss for party i:
                let key_i = BigInt::to_vec(&enc_keys[j]);
                let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
                let aead_pack_i = aes_encrypt(&key_i, &plaintext);
                assert!(sendp2p(
                    &addr,
                    //&client,
                    *n as u16,
                    i,
                    "round3",
                    serde_json::to_string(&aead_pack_i).unwrap(),
                    uuids_i[*n - 1].clone(),
                    shm,
                )
                .is_ok());
                j += 1;
            }
        }
        point_vec_i.push(point_vec);
        decom_vec_i.push(decom_vec);
        enc_keys_i.push(enc_keys);
        vss_scheme_i.push(vss_scheme);
        secret_shares_i.push(secret_shares);
    }

/////////////////////////////////////////////////////////////////////////
    let mut round3_ans_vec_i = vec![];
    for n in part_num_int.iter(){
        let round3_ans_vec = poll_for_p2p(
            &addr,
            //&client,
            *n as u16,
            PARTIES,
            delay,
            "round3",
            uuids_i[*n - 1].clone(),
            shm,
        );
        round3_ans_vec_i.push(round3_ans_vec);
    }

    let mut party_shares_i = vec![];

    for n in part_num_int.iter(){
        let mut j = 0;
        let mut party_shares: Vec<FE> = Vec::new();
        for i in 1..=PARTIES {
            if i == *n as u16 {
                party_shares.push(secret_shares_i[*n - 1][(i - 1) as usize]);
            } else {
                let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec_i[*n - 1][j]).unwrap();
                let key_i = BigInt::to_vec(&enc_keys_i[*n - 1][j]);
                let out = aes_decrypt(&key_i, aead_pack);
                let out_bn = BigInt::from(&out[..]);
                let out_fe = ECScalar::from(&out_bn);
                party_shares.push(out_fe);

                j += 1;
            }
        }
        party_shares_i.push(party_shares);
        // round 4: send vss commitments
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round4",
            serde_json::to_string(&vss_scheme_i[*n - 1]).unwrap(),
            uuids_i[*n - 1].clone(),
            shm,
        )
        .is_ok());
    }

////////////////////////////////////////////////////////////////////////////////

    let mut round4_ans_vec_i = vec![];
    let mut vss_scheme_vec_i = vec![];
    for n in part_num_int.iter(){
        let round4_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            PARTIES,
            delay,
            "round4",
            uuids_i[*n - 1].clone(),
            shm,
        );
        round4_ans_vec_i.push(round4_ans_vec);
    }




////////////////////////////////////////////////////////////////////////////////
    let mut shared_keys_i = vec![];
    let mut dlog_proof_i = vec![];
    for n in part_num_int.iter(){
        let mut j = 0;
        let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
        for i in 1..=PARTIES {
            if i == *n as u16 {
                vss_scheme_vec.push(vss_scheme_i[*n - 1].clone());
            } else {
                let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec_i[*n - 1][j]).unwrap();
                vss_scheme_vec.push(vss_scheme_j);
                j += 1;
            }
        }

        let (shared_keys, dlog_proof) = party_keys[*n -1]
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &point_vec_i[*n - 1],
                &party_shares_i[*n - 1],
                &vss_scheme_vec,
                *n as usize,
            )
            .expect("invalid vss");

        // round 5: send dlog proof
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round5",
            serde_json::to_string(&dlog_proof).unwrap(),
            uuids_i[*n -1].clone(),
            shm,
        )
        .is_ok());
        vss_scheme_vec_i.push(vss_scheme_vec);
        shared_keys_i.push(shared_keys);
        dlog_proof_i.push(dlog_proof);
    }


    /////////////////////////////////////////////////////////////////////////////
    /// 
    let mut round5_ans_vec_i = vec![];

    for n in part_num_int.iter(){
        let round5_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            PARTIES,
            delay,
            "round5",
            uuids_i[*n -1].clone(),
            shm,
        );
        round5_ans_vec_i.push(round5_ans_vec);
    }
    //////////////////////////////////////////////////////////////////////////////
    /// 
    /// 
    for n in part_num_int.iter(){
        let mut j = 0;
        let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
        for i in 1..=PARTIES {
            if i == *n as u16 {
                dlog_proof_vec.push(dlog_proof_i[*n - 1].clone());
            } else {
                let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec_i[*n - 1][j]).unwrap();
                dlog_proof_vec.push(dlog_proof_j);
                j += 1;
            }
        }
        Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec_i[*n -1]).expect("bad dlog proof");

        //save key to file:
        let paillier_key_vec = (0..PARTIES)
            .map(|i| bc_vec_i[*n-1][i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
      
        let keygen_json = serde_json::to_string(&(
            party_keys[*n-1].clone(),
            shared_keys_i[*n-1].clone(),
            *n as u16,
            vss_scheme_vec_i[*n-1].clone(),
            paillier_key_vec,
            y_sum_i[*n - 1].clone(),
        ))
        .unwrap();
        info!("Keys data written to file: {:?}", keysfile_path_i[*n - 1]);
        fs::write(&keysfile_path_i[*n -1], keygen_json).expect("Unable to save !");
    }
}

/*#[derive(serde::Serialize, serde::Deserialize)]
struct KeyGenResult {
    party_keys: Keys,
    shared_keys:,
    party_number: u16,
    vss_scheme_vec_i:,
    paillier_key_vec:,
    y_sum:, 
}
*/
pub fn keygen_signup(
    addr: &String,
    //client: &Client,
    params: &Params,
    shm: &mut gs) -> Result<PartySignup, ()> {
    use crate::manager::signup_keygen;
    signup_keygen((*params).clone(), shm)
    /*let res_body = postb(
        &addr,
        //&client,
        "signupkeygen",
        params, shm).unwrap();
    */

    //serde_json::from_str(&res_body).unwrap()
}
#[cfg(test)]
mod test{
    #[test]
    fn test_round1(){
        use crate::keygen::key_round1;
        let party1 = r#"{"data": {"party":1}}"#;
        
        let r = key_round1(party1.to_string());
        match r {
            Ok(ok) => println!("{}", ok),
            Err(err) => println!("{}", err),
        }

    }
}