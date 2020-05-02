use std::collections::HashMap;
use std::sync::{RwLock, Mutex, Arc};
use std::time;
//use rocket::{post, routes, State};
//use rocket_contrib::json::Json;
use uuid::Uuid;

type gs = Arc<Mutex<HashMap<Key, String>>>;

use crate::common::{Entry, Index, Key, Params, PartySignup};
use serde_json;

use log::info;
//static db_cell: HashMap<Key, String> = HashMap::new());
pub fn run_manager(shm: &gs) {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    //let db: HashMap<Key, String> = HashMap::new();
    //let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = PartySignup {
        number: party1,
        uuid: uuid_sign,
    };
    {
        //let mut hm = db_mtx.write().unwrap();
        let mut db = shm.lock().unwrap();
        db.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        db.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
    }
    /////////////////////////////////////////////////////////////////
    //rocket::ignite()
    //    .mount("/", routes![get, set, signup_keygen, signup_sign])
    //    .manage(db_mtx)
    //    .launch();
}

//#[post("/get", format = "json", data = "<request>")]
pub fn get(
    //db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Index,
    shm: &gs
//) -> Json<Result<Entry, ()>> {
) -> Result<Entry, ()> {
    //let index: Index = request.0;
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250); 
    for _ in 0..retries {
        let hm = shm.lock().unwrap();
    //let mut hm = db_cell.borrow_mut();
        match hm.get(&request.key) {
            Some(v) => {
                let entry = Entry {
                    key: request.key,
                    value: v.clone().to_string(),
                };
                return Ok(entry)
            }
            None => {continue;},
        }
    }
    Err(())
}

//#[post("/set", format = "json", data = "<request>")]
//fn set(db_mtx: State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
pub fn set(request: Entry, shm: &gs) -> Result<(), ()> {

    let mut hm = shm.lock().unwrap();
    //let mut hm = db_cell.borrow_mut();
    hm.insert(request.key.clone(), request.value.clone());
    Ok(())
}

//#[post("/signupkeygen", format = "json", data = "<request>")]
pub fn signup_keygen(
//    db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Params,
    shm: &gs
//) -> Json<Result<PartySignup, ()>> {
) -> Result<PartySignup, ()> {
    let parties = request.parties.parse::<u16>().unwrap();
    let key = "signup-keygen".to_string();

    let party_signup = {

        let hm = shm.lock().unwrap();
        //let mut hm = db_cell.borrow_mut();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = shm.lock().unwrap();
    //let mut hm = db_cell.borrow_mut();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Ok(party_signup)
}

//#[post("/signupsign", format = "json", data = "<request>")]
pub fn signup_sign(
//    db_mtx: State<RwLock<HashMap<Key, String>>>,
//    request: Json<Params>,
    request: Params,
    shm: &gs
//) -> Json<Result<PartySignup, ()>> {
) -> Result<PartySignup, ()> {
    let threshold = request.threshold.parse::<u16>().unwrap();
    let key = "signup-sign".to_string();

    let party_signup = {
        
        let hm = shm.lock().unwrap();
        //let mut hm = db_cell.borrow_mut();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < threshold + 1 {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = shm.lock().unwrap();
    //let mut hm = db_cell.borrow_mut();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Ok(party_signup)
}
