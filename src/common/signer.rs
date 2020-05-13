extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
//extern crate reqwest;
extern crate serde_json;

use std::time;
use std::sync::{Arc, Mutex};
use crate::common::{Entry, Index, Key};
use std::collections::HashMap;
type gs = HashMap<Key, String, crate::random_state::PsRandomState>;

use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
//use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::{broadcast, poll_for_broadcasts, poll_for_p2p, sendp2p, Params, PartySignup};
use crate::common::keygen::KeyGenResult;

use log::info;
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TupleKey {
    pub first: String,
    pub second: String,
    pub third: String,
    pub fourth: String,
}

pub fn sign(
    keygen_result: Vec<KeyGenResult>,
    //addr: String,
    //party_keys: Keys,
    //shared_keys: SharedKeys,
    //party_id: u16,
    //vss_scheme_vec: &mut Vec<VerifiableSS>,
    //paillier_key_vector: Vec<EncryptionKey>,
    //y_sum: &GE,
    params: &Params,
    message: &[u8],
    f_l_new: &FE,
    sign_at_path: bool,
    shm: &mut gs
) {
    //let client = Client::new();
    let addr = String::from("dummy");
    let delay = time::Duration::from_millis(25);
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();
    let mut uuid_i = vec![];
    let party_num_int_i: [usize; 3] = [1,2,3];
    for n in party_num_int_i.iter() {
    // Signup
        let (party_num_int, uuid) = match signup(
            &addr,
            //&client,
            &params, shm).unwrap() {
            PartySignup { number, uuid } => (number, uuid),
        };
        uuid_i.push(uuid.clone());

        let debug = json!({"manager_addr": &addr, "party_num": party_num_int, "uuid": uuid});
        info!("{}", serde_json::to_string_pretty(&debug).unwrap());


        // round 0: collect signers IDs
        assert!(broadcast(
            &addr,
            //&client,
            party_num_int,
            "round0",
            serde_json::to_string(n).unwrap(),
            uuid.clone(),
            shm
        )
        .is_ok());
    }
    let mut round0_ans_vec_i = vec![];
    for n in party_num_int_i.iter(){
        let round0_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay,
            "round0",
            uuid_i[*n].clone(),
            shm,
        );
        round0_ans_vec_i.push(round0_ans_vec);
    }   

    let mut signers_vec: Vec<usize> = Vec::new();
    for n in party_num_int_i.iter(){
        let mut j = 0;
        for i in 1..=THRESHOLD + 1 {
            if i == *n as u16 {
                signers_vec.push((*n - 1) as usize);
            } else {
                let signer_j: u16 = serde_json::from_str(&round0_ans_vec_i[*n - 1][j]).unwrap();
                signers_vec.push((signer_j - 1) as usize);
                j = j + 1;
            }
        }
    }   
    /*
    if sign_at_path == true {
        // optimize!
        let g: GE = ECPoint::generator();
        // apply on first commitment for leader (leader is party with num=1)
        let com_zero_new = vss_scheme_vec[0].commitments[0] + g * f_l_new;
        // info!("old zero: {:?}, new zero: {:?}", vss_scheme_vec[0].commitments[0], com_zero_new);
        // get iterator of all commitments and skip first zero commitment
        let mut com_iter_unchanged = vss_scheme_vec[0].commitments.iter();
        com_iter_unchanged.next().unwrap();
        // iterate commitments and inject changed commitments in the beginning then aggregate into vector
        let com_vec_new = (0..vss_scheme_vec[1].commitments.len())
            .map(|i| {
                if i == 0 {
                    com_zero_new
                } else {
                    com_iter_unchanged.next().unwrap().clone()
                }
            })
            .collect::<Vec<GE>>();
        let new_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: com_vec_new,
        };
        // replace old vss_scheme for leader with new one at position 0
        //    info!("comparing vectors: \n{:?} \nand \n{:?}", vss_scheme_vec[0], new_vss);

        vss_scheme_vec.remove(0);
        vss_scheme_vec.insert(0, new_vss);
        //    info!("NEW VSS VECTOR: {:?}", vss_scheme_vec);
    }
    */
    let mut private_i = vec![];
    let mut com_i = vec![];
    let mut decommit_i = vec![];
    let mut m_a_k_i = vec![];
    let mut sign_keys_i = vec![];
    for n in party_num_int_i.iter(){
        let mut private = PartyPrivate::set_private(keygen_result[*n-1].party_keys.clone(), keygen_result[*n - 1].shared_keys.clone());
        /*
        if sign_at_path == true {
            if party_num_int == 1 {
                // update u_i and x_i for leader
                private = private.update_private_key(&f_l_new, &f_l_new);
            } else {
                // only update x_i for non-leaders
                private = private.update_private_key(&FE::zero(), &f_l_new);
            }
        }
        */

        let sign_keys = SignKeys::create(
            &private,
            &keygen_result[*n -1].vss_scheme_vec_i[signers_vec[(*n - 1) as usize]],
            signers_vec[(*n - 1) as usize],
            &signers_vec,
        );

        //////////////////////////////////////////////////////////////////////////////
        let (com, decommit) = sign_keys.phase1_broadcast();
        let m_a_k = MessageA::a(&sign_keys.k_i, &keygen_result[*n - 1].party_keys.clone().ek);
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round1",
            serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
            uuid_i[*n - 1].clone(),
            shm
        )
        .is_ok());
        private_i.push(private);
        com_i.push(com);
        decommit_i.push(decommit);
        m_a_k_i.push(m_a_k);
        sign_keys_i.push(sign_keys);
    }
    let mut round1_ans_vec_i = vec![];
    for n in party_num_int_i.iter(){
        let round1_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay,
            "round1",
            uuid_i[*n - 1].clone(),
            shm
        );
        round1_ans_vec_i.push(round1_ans_vec);
    }

    let mut bc1_vec_i = vec![];
    let mut m_a_vec_i = vec![];
    let mut beta_vec_i = vec![];
    let mut ni_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let mut j = 0;
        let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
        let mut m_a_vec: Vec<MessageA> = Vec::new();

        for i in 1..THRESHOLD + 2 {
            if i == *n as u16 {
                bc1_vec.push(com_i[*n -1].clone());
            //   m_a_vec.push(m_a_k.clone());
            } else {
                //     if signers_vec.contains(&(i as usize)) {
                let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                    serde_json::from_str(&round1_ans_vec_i[*n-1][j]).unwrap();
                bc1_vec.push(bc1_j);
                m_a_vec.push(m_a_party_j);

                j = j + 1;
                //       }
            }
        }
        assert_eq!(signers_vec.len(), bc1_vec.len());
    
        bc1_vec_i.push(bc1_vec);

        //////////////////////////////////////////////////////////////////////////////
        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec: Vec<FE> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut ni_vec: Vec<FE> = Vec::new();
        j = 0;
        for i in 1..THRESHOLD + 2 {
            if i != *n as u16 {
                let (m_b_gamma, beta_gamma) = MessageB::b(
                    &sign_keys_i[*n - 1].gamma_i,
                    &keygen_result[*n - 1].paillier_key_vector[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                let (m_b_w, beta_wi) = MessageB::b(
                    &sign_keys_i[*n-1].w_i,
                    &keygen_result[*n-1].paillier_key_vector[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                m_b_gamma_send_vec.push(m_b_gamma);
                m_b_w_send_vec.push(m_b_w);
                beta_vec.push(beta_gamma);
                ni_vec.push(beta_wi);
                j = j + 1;
            }
        }
        beta_vec_i.push(beta_vec);
        ni_vec_i.push(ni_vec);

        j = 0;
        for i in 1..THRESHOLD + 2 {
            if i != *n as u16  {
                assert!(sendp2p(
                    &addr,
                    //&client,
                    *n as u16,
                    i.clone(),
                    "round2",
                    serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                        .unwrap(),
                    uuid_i[*n - 1].clone(),
                    shm,
                )
                .is_ok());
                j = j + 1;
            }
        }
    }


    let mut round2_ans_vec_i = vec![]; 
    for n in party_num_int_i.iter() {
        let round2_ans_vec = poll_for_p2p(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay,
            "round2",
            uuid_i[*n-1].clone(),
            shm,
        );
        round2_ans_vec_i.push(round2_ans_vec);
    }

//////////////////////////////////////////////////////////////////////////////
/// 
/// 
/// 
    let mut delta_i_i = vec![];
    let mut m_b_gamma_rec_vec_i = vec![];
    let mut sigma_i = vec![];
    for n in party_num_int_i.iter() {
        let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
        let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

        for i in 0..THRESHOLD {
            //  if signers_vec.contains(&(i as usize)) {
            let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
                serde_json::from_str(&round2_ans_vec_i[*n-1][i as usize]).unwrap();
            m_b_gamma_rec_vec.push(m_b_gamma_i);
            m_b_w_rec_vec.push(m_b_w_i);
            //     }
        }

        let mut alpha_vec: Vec<FE> = Vec::new();
        let mut miu_vec: Vec<FE> = Vec::new();

        let xi_com_vec = Keys::get_commitments_to_xi(&keygen_result[*n-1].vss_scheme_vec_i.clone());
        let mut j = 0;
        for i in 1..THRESHOLD + 2 {
            //        info!("mbproof p={}, i={}, j={}", party_num_int, i, j);
            if i != *n as u16 {
                //            info!("verifying: p={}, i={}, j={}", party_num_int, i, j);
                let m_b = m_b_gamma_rec_vec[j].clone();

                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&keygen_result[*n-1].party_keys.dk, &sign_keys_i[*n-1].k_i)
                    .expect("wrong dlog or m_b");
                let m_b = m_b_w_rec_vec[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&keygen_result[*n-1].party_keys.dk, &sign_keys_i[*n-1].k_i)
                    .expect("wrong dlog or m_b");
                alpha_vec.push(alpha_ij_gamma);
                miu_vec.push(alpha_ij_wi);
                let g_w_i = Keys::update_commitments_to_xi(
                    &xi_com_vec[signers_vec[(i - 1) as usize]],
                    &keygen_result[*n-1].vss_scheme_vec_i[signers_vec[(i - 1) as usize]],
                    signers_vec[(i - 1) as usize],
                    &signers_vec,
                );
                //info!("Verifying client {}", party_num_int);
                assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
                //info!("Verified client {}", party_num_int);
                j = j + 1;
            }
        }
        //////////////////////////////////////////////////////////////////////////////
        let delta_i = sign_keys_i[*n-1].phase2_delta_i(&alpha_vec, &beta_vec_i[*n-1]);
        let sigma = sign_keys_i[*n-1].phase2_sigma_i(&miu_vec, &ni_vec_i[*n-1]);

        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round3",
            serde_json::to_string(&delta_i).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        delta_i_i.push(delta_i);
        m_b_gamma_rec_vec_i.push(m_b_gamma_rec_vec);
        sigma_i.push(sigma);
    }

    let mut round3_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round3_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay,
            "round3",
            uuid_i[*n-1].clone(),
            shm
        );
        round3_ans_vec_i.push(round3_ans_vec);
    }

    let mut delta_inv_i = vec![];
    for n in party_num_int_i.iter() {
        let mut delta_vec: Vec<FE> = Vec::new();
        format_vec_from_reads(
            &round3_ans_vec_i[*n-1],
            *n  as usize,
            delta_i_i[*n-1].clone(),
            &mut delta_vec,
        );
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        delta_inv_i.push(delta_inv);
        //////////////////////////////////////////////////////////////////////////////
        // decommit to gamma_i
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round4",
            serde_json::to_string(&decommit_i[*n-1]).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
    }
    let mut round4_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round4_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay,
            "round4",
            uuid_i[*n-1].clone(),
            shm
        );
        round4_ans_vec_i.push(round4_ans_vec);
    }


    let message_bn = BigInt::from(message);

    let message_int = BigInt::from(message);
    let mut phase5_com_i = vec![];
    let mut phase_5a_decom_i = vec![];
    let mut helgamal_proof_i = vec![];
    let local_sig_i = vec![];
    let mut R_i = vec![];
    for n in party_num_int_i.iter() {
        let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
        format_vec_from_reads(
            &round4_ans_vec_i[*n-1],
            *n as usize,
            decommit_i[*n-1].clone(),
            &mut decommit_vec,
        );
        let decomm_i = decommit_vec.remove((*n - 1) as usize);
        bc1_vec_i[*n-1].remove((*n - 1) as usize);
        let b_proof_vec = (0..m_b_gamma_rec_vec_i[*n-1].len())
            .map(|i| &m_b_gamma_rec_vec_i[*n-1][i].b_proof)
            .collect::<Vec<&DLogProof>>();
        let R = SignKeys::phase4(&delta_inv_i[*n-1], &b_proof_vec, decommit_vec, &bc1_vec_i[*n-1])
            .expect("bad gamma_i decommit");

        // adding local g_gamma_i
        let R = R + decomm_i.g_gamma_i * &delta_inv_i[*n-1];
        
        // we assume the message is already hashed (by the signer).
        //    info!("message_bn INT: {}", message_bn);
        let two = BigInt::from(2);
        let message_bn = message_bn.modulus(&two.pow(256));
        let local_sig =
            LocalSignature::phase5_local_sig(&sign_keys_i[*n-1].k_i, &message_bn, &R, &sigma_i[*n-1], &keygen_result[*n-1].y_sum);

        let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();
        
        //phase (5A)  broadcast commit
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round5",
            serde_json::to_string(&phase5_com).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        phase5_com_i.push(phase5_com);
        phase_5a_decom_i.push(phase_5a_decom);
        helgamal_proof_i.push(helgamal_proof);
        local_sig_i.push(local_sig);
        R_i.push(R);
    }


    let mut round5_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round5_ans_vec = poll_for_broadcasts(
                &addr,
                //&client,
                *n as u16,
                THRESHOLD + 1,
                delay.clone(),
                "round5",
                uuid_i[*n-1].clone(),
                shm
            );
        round5_ans_vec_i.push(round5_ans_vec);
    }


    let mut commit5a_vec_i = vec![]; 
    for n in party_num_int_i.iter() {
        let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
        format_vec_from_reads(
            &round5_ans_vec_i[*n-1],
            *n as usize,
            phase5_com_i[*n-1],
            &mut commit5a_vec,
        );

        //phase (5B)  broadcast decommit and (5B) ZK proof
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round6",
            serde_json::to_string(&(phase_5a_decom_i[*n-1].clone(), helgamal_proof_i[*n-1].clone())).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        commit5a_vec_i.push(commit5a_vec);
    }


    let mut round6_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round6_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay.clone(),
            "round6",
            uuid_i[*n-1].clone(),
            shm
        );
        round0_ans_vec_i.push(round6_ans_vec);
    }

    let mut phase5_com2_i = vec![];
    let mut phase_5d_decom2_i = vec![];
    let mut decommit5a_and_elgamal_vec_includes_i_i = vec![];
    for n in party_num_int_i.iter() {
        let mut decommit5a_and_elgamal_vec: Vec<(Phase5ADecom1, HomoELGamalProof)> = Vec::new();
        format_vec_from_reads(
            &round6_ans_vec_i[*n-1],
            *n as usize,
            (phase_5a_decom_i[*n-1].clone(), helgamal_proof_i[*n-1].clone()),
            &mut decommit5a_and_elgamal_vec,
        );
        let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
        decommit5a_and_elgamal_vec.remove((*n - 1) as usize);
        commit5a_vec_i[*n-1].remove((*n - 1) as usize);
        let phase_5a_decomm_vec = (0..THRESHOLD)
            .map(|i| decommit5a_and_elgamal_vec[i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();
        let phase_5a_elgamal_vec = (0..THRESHOLD)
            .map(|i| decommit5a_and_elgamal_vec[i as usize].1.clone())
            .collect::<Vec<HomoELGamalProof>>();
        let (phase5_com2, phase_5d_decom2) = local_sig_i[*n-1]
            .phase5c(
                &phase_5a_decomm_vec,
                &commit5a_vec_i[*n-1],
                &phase_5a_elgamal_vec,
                &phase_5a_decom_i[*n-1].V_i,
                &R_i[*n-1].clone(),
            )
            .expect("error phase5");

        //////////////////////////////////////////////////////////////////////////////
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round7",
            serde_json::to_string(&phase5_com2).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        phase5_com2_i.push(phase5_com2);
        phase_5d_decom2_i.push(phase_5d_decom2);
        decommit5a_and_elgamal_vec_includes_i_i.push(decommit5a_and_elgamal_vec_includes_i);
    }

    let mut round7_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round7_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16 ,
            THRESHOLD + 1,
            delay.clone(),
            "round7",
            uuid_i[*n-1].clone(),
            shm
        );
        round7_ans_vec_i.push(round7_ans_vec);
    }
    let mut commit5c_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
        format_vec_from_reads(
            &round7_ans_vec_i[*n-1],
            *n as usize,
            phase5_com2_i[*n-1],
            &mut commit5c_vec,
        );

        //phase (5B)  broadcast decommit and (5B) ZK proof
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round8",
            serde_json::to_string(&phase_5d_decom2_i[*n-1]).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        commit5c_vec_i.push(commit5c_vec);
    }

    let mut round8_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round8_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16,
            THRESHOLD + 1,
            delay.clone(),
            "round8",
            uuid_i[*n-1].clone(),
            shm
        );
        round8_ans_vec_i.push(round8_ans_vec);
    }
    let mut s_i_i = vec![];
    for n in party_num_int_i.iter() {
        let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
        format_vec_from_reads(
            &round8_ans_vec_i[*n-1],
            *n as usize,
            phase_5d_decom2_i[*n-1].clone(),
            &mut decommit5d_vec,
        );

        let phase_5a_decomm_vec_includes_i = (0..THRESHOLD + 1)
            .map(|i| decommit5a_and_elgamal_vec_includes_i_i[*n-1][i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();
        let s_i = local_sig_i[*n-1]
            .phase5d(
                &decommit5d_vec,
                &commit5c_vec_i[*n-1],
                &phase_5a_decomm_vec_includes_i,
            )
            .expect("bad com 5d");

        //////////////////////////////////////////////////////////////////////////////
        assert!(broadcast(
            &addr,
            //&client,
            *n as u16,
            "round9",
            serde_json::to_string(&s_i).unwrap(),
            uuid_i[*n-1].clone(),
            shm
        )
        .is_ok());
        s_i_i.push(s_i);
    }
    let mut round9_ans_vec_i = vec![];
    for n in party_num_int_i.iter() {
        let round9_ans_vec = poll_for_broadcasts(
            &addr,
            //&client,
            *n as u16 ,
            THRESHOLD + 1,
            delay.clone(),
            "round9",
            uuid_i[*n-1],
            shm
        );
        round9_ans_vec_i.push(round9_ans_vec);
    }

    for n in party_num_int_i.iter() {
        let mut s_i_vec: Vec<FE> = Vec::new();
        format_vec_from_reads(
            &round9_ans_vec_i[*n-1],
            *n as usize,
            s_i_i[*n-1],
            &mut s_i_vec,
        );

        s_i_vec.remove((*n - 1) as usize);
        let sig = local_sig_i[*n-1]
            .output_signature(&s_i_vec)
            .expect("verification failed");
        //    info!(" \n");
        //    info!("party {:?} Output Signature: \n", party_num_int);
        //    info!("SIG msg: {:?}", sig.m);
        //    info!("R: {:?}", sig.r);
        //    info!("s: {:?} \n", sig.s);
        //    info!("child pubkey: {:?} \n", y_sum);

        //    info!("pubkey: {:?} \n", y_sum);
        //    info!("verifying signature with public key");
        verify(&sig, &keygen_result[*n-1].y_sum, &message_bn).expect("false");
        //    info!("verifying signature with child pub key");
        //    verify(&sig, &new_key, &message_bn).expect("false");

        //    info!("{:?}", sig.recid.clone());
        //    print(sig.recid.clone()

        let ret_dict = json!({
            "r": (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
            "s": (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
            "status": "signature_ready",
            "recid": sig.recid.clone(),
            "x": &keygen_result[*n-1].y_sum.x_coor(),
            "y": &keygen_result[*n-1].y_sum.y_coor(),
            "msg_int": message_int,
        });
        info!("{}", ret_dict.to_string());
    }

    //    fs::write("signature".to_string(), sign_json).expect("Unable to save !");

    //    info!("Public key Y: {:?}", to_bitcoin_public_key(y_sum.get_element()).to_bytes());
    //    info!("Public child key X: {:?}", &new_key.x_coor());
    //    info!("Public child key Y: {:?}", &new_key.y_coor());
    //    info!("Public key big int: {:?}", &y_sum.bytes_compressed_to_big_int());
    //    info!("Public key ge: {:?}", &y_sum.get_element().serialize());
    //    info!("Public key ge: {:?}", PK::serialize_uncompressed(&y_sum.get_element()));
    //    info!("New public key: {:?}", &y_sum.x_coor);
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j = j + 1;
        }
    }
}
/*
pub fn postb<T>(
    addr: &String,
    //client: &Client,
    path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let res = post(&format!("{}/{}", addr, path))
        .json(&body)
        .send();
    Some(res.unwrap().text().unwrap())
}
*/
pub fn signup(
     addr: &String,
     //client: &Client,
     params: &Params,
     shm: &mut gs) -> Result<PartySignup, ()> {
    use crate::manager::signup_sign;
    signup_sign((*params).clone(), shm)
    /*let res_body = postb(&addr,
        // &client,
         "signupsign", params, shm).unwrap();
    let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
    */
}
