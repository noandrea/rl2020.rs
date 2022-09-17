use base64::{decode_config, encode_config, STANDARD};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::io::prelude::*;
use std::str::FromStr;
use std::vec::Vec;
use wasm_bindgen::prelude::*;

const REVOCATION_LIST_2020_TYPE: &str = "RevocationList2020";
const REVOCATION_LIST_2020_STATUS_TYPE: &str = "RevocationList2020Status";
// Minimum bitstring size is 16kb
const MIN_BITSTRING_SIZE_KN: usize = 16;
// Maximum bistsring size is 128kb
const MAX_BITSTRING_SIZE_KB: usize = 128;

/// CredentialStatus represent the status block of a credential issued using the RevocationList2020
/// as a revocation method. See https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020status
pub trait CredentialStatus {
    /// returns the credential list ID to check for revocation,
    /// and the index within the list, that is:
    /// - revocationListCredential
    /// - revocationListIndex
    fn coordinates(&self) -> (String, u64);
    /// returns the ID and the Type of the credential status itself, that is
    /// - ID
    /// - Type
    fn type_def(&self) -> (String, String);
}

#[derive(Debug)]
pub struct CredentialError {
    message: String,
}

impl CredentialError {
    pub fn new(msg: &str) -> Self {
        CredentialError {
            message: String::from(msg),
        }
    }
}

impl Display for CredentialError {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, PartialEq)]
pub enum RevocationStatus {
    Revoke,
    Reset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList2020 {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(rename = "encodedList")]
    encoded_list: String,
    #[serde(skip)]
    bit_set: Vec<u8>,
}

impl Display for RevocationList2020 {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

impl FromStr for RevocationList2020 {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut rl =
            serde_json::from_str::<Self>(s).map_err(|e| CredentialError::new(&e.to_string()))?;
        // check the revocation list id
        if rl.id.trim().is_empty() {
            return Err(CredentialError::new("revocation list id cannot be empty"));
        }
        // check the revocation list type
        if rl.typ != REVOCATION_LIST_2020_TYPE {
            return Err(CredentialError::new("unrecognized revocation list typoe"));
        }
        // decode the bit string
        rl.bit_set = RevocationList2020::unpack(&rl.encoded_list)?;
        Ok(rl)
    }
}

impl RevocationList2020 {
    fn pack(data: &Vec<u8>) -> Result<String, CredentialError> {
        // compress the data
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        // TODO: handle errors
        e.write_all(data)
            .map_err(|e| CredentialError::new(&e.to_string()))?;
        let compressed = e
            .finish()
            .map_err(|e| CredentialError::new(&e.to_string()))?;
        // encode the data
        Ok(encode_config(&compressed, STANDARD))
    }

    fn unpack(data: &String) -> Result<Vec<u8>, CredentialError> {
        let bin =
            decode_config(&data, STANDARD).map_err(|e| CredentialError::new(&e.to_string()))?;
        let mut d = ZlibDecoder::new(&*bin);
        let mut buf = Vec::new();
        d.read_to_end(&mut buf)
            .map_err(|e| CredentialError::new(&e.to_string()))?;
        Ok(buf)
    }

    fn check_bounds(&self, index: u64) -> Result<(), CredentialError> {
        match index {
            i if (i as usize) >= self.capacity() => Err(CredentialError::new(&format!(
                "max indexable element is {}, provided index {} is out of range",
                self.capacity(),
                i,
            ))),
            _ => Ok(()),
        }
    }

    pub fn new(id: &str, size: usize) -> Result<Self, CredentialError> {
        if size < MIN_BITSTRING_SIZE_KN {
            return Err(CredentialError::new(&format!(
                "minimum credential size is {}, got {}",
                MIN_BITSTRING_SIZE_KN, size
            )));
        }
        if size > MAX_BITSTRING_SIZE_KB {
            return Err(CredentialError::new(&format!(
                "maximum credential size is {}, got {}",
                MIN_BITSTRING_SIZE_KN, size
            )));
        }
        if id.trim().is_empty() {
            return Err(CredentialError::new("revocation list id cannot be empty"));
        }
        // initialize the bitset
        let bs = vec![0; size * 1024];
        let el = Self::pack(&bs)?;

        Ok(RevocationList2020 {
            id: String::from(id),
            typ: String::from(REVOCATION_LIST_2020_TYPE),
            encoded_list: el,
            bit_set: bs,
        })
    }

    pub fn capacity(&self) -> usize {
        self.bit_set.len() * 8
    }

    // size returns the size of the bitset int kb
    pub fn size(&self) -> usize {
        return self.bit_set.len() / 1024;
    }

    pub fn update(&mut self, action: RevocationStatus, index: u64) -> Result<(), CredentialError> {
        self.check_bounds(index)?;

        let pos = (index / 8) as usize;
        let j = (index % 8) as u8;

        match action {
            RevocationStatus::Revoke => self.bit_set[pos] |= 1 << j,
            RevocationStatus::Reset => self.bit_set[pos] &= !(1 << j),
        };
        self.encoded_list = Self::pack(&self.bit_set)?;
        Ok(())
    }

    pub fn get(&self, index: u64) -> Result<RevocationStatus, CredentialError> {
        self.check_bounds(index)?;

        let pos = (index / 8) as usize;
        let j = (index % 8) as u8;

        match self.bit_set[pos] & (1 << j) {
            0 => Ok(RevocationStatus::Reset),
            _ => Ok(RevocationStatus::Revoke),
        }
    }

    fn check_ids(&self, credential: &impl CredentialStatus) -> Result<u64, CredentialError> {
        // check type
        if credential.type_def().1 != REVOCATION_LIST_2020_STATUS_TYPE {
            return Err(CredentialError::new(&format!(
                "credential status type doesn't match {}",
                REVOCATION_LIST_2020_STATUS_TYPE
            )));
        }
        // check coordinates
        let coords = credential.coordinates();
        if coords.0 != self.id {
            return Err(CredentialError::new(&format!(
                "credential status doesn't match the current revocation lists, expected {}, got {}",
                self.id, coords.0,
            )));
        }
        Ok(coords.1)
    }

    pub fn revoke(&mut self, credential: &impl CredentialStatus) -> Result<(), CredentialError> {
        self.check_ids(credential)
            .and_then(|i| self.update(RevocationStatus::Revoke, i))
    }

    pub fn reset(&mut self, credential: &impl CredentialStatus) -> Result<(), CredentialError> {
        self.check_ids(credential)
            .and_then(|i| self.update(RevocationStatus::Reset, i))
    }

    pub fn is_revoked(&self, credential: &impl CredentialStatus) -> Result<bool, CredentialError> {
        self.check_ids(credential).and_then(|i| {
            self.get(i).map(|x| match x {
                RevocationStatus::Revoke => true,
                RevocationStatus::Reset => false,
            })
        })
    }
}

#[cfg(test)]
mod tests {

    use super::{
        CredentialStatus, RevocationList2020, RevocationStatus, REVOCATION_LIST_2020_STATUS_TYPE,
    };
    use rand::Rng;
    use std::str::FromStr;

    #[test]
    fn test_create() {
        // FAIL: size too big
        let rl = RevocationList2020::new("test-1", 1000);
        assert_eq!(rl.is_err(), true);

        // FAIL: size to small
        let rl = RevocationList2020::new("test-1", 15);
        assert_eq!(rl.is_err(), true);

        // FAIL: empty id
        let rl = RevocationList2020::new(" ", 16);
        assert_eq!(rl.is_err(), true);

        // PASS: all good
        let rl = RevocationList2020::new("test-1", 22);
        assert_eq!(rl.is_err(), false);
    }

    #[test]
    fn test_update() {
        // this is ok
        let rl = RevocationList2020::new("test-1", 16);
        assert_eq!(rl.is_err(), false);
        let mut rl = rl.unwrap();

        let mut r = rand::thread_rng();

        for _ in 1..100 {
            let credential_index = r.gen_range(0..rl.capacity()) as u64;

            let up = rl.update(RevocationStatus::Revoke, credential_index);
            assert_eq!(up.is_err(), false);

            let get = rl.get(credential_index);
            assert_eq!(get.is_err(), false);
            let get = get.unwrap();
            assert_eq!(get, RevocationStatus::Revoke);

            let up = rl.update(RevocationStatus::Reset, credential_index);
            assert_eq!(up.is_err(), false);

            let get = rl.get(credential_index);
            assert_eq!(get.is_err(), false);
            let get = get.unwrap();
            assert_eq!(get, RevocationStatus::Reset);
        }

        // update out of scope
        let up = rl.update(RevocationStatus::Revoke, 200_000_000);
        assert_eq!(up.is_err(), true);

        println!("{}", rl);
    }

    #[test]
    fn test_credential_status() {
        let rl = RevocationList2020::new("https://example.rl/1", 60);
        assert_eq!(rl.is_err(), false);
        let mut rl = rl.unwrap();

        struct VC {
            id: String,
            typ: String,
            rl_id: String,
            rl_idx: u64,
        }
        impl VC {
            pub fn new(id: &str, typ: &str, rl_id: &str, rl_idx: u64) -> Self {
                VC {
                    id: String::from(id),
                    typ: String::from(typ),
                    rl_id: String::from(rl_id),
                    rl_idx: rl_idx,
                }
            }
        }
        impl CredentialStatus for VC {
            fn type_def(&self) -> (String, String) {
                (self.id.to_owned(), self.typ.to_owned())
            }
            fn coordinates(&self) -> (String, u64) {
                (self.rl_id.to_owned(), self.rl_idx)
            }
        }

        let tests = vec![
            (
                VC::new(
                    "test-1#213",
                    REVOCATION_LIST_2020_STATUS_TYPE,
                    "https://example.rl/1",
                    8743,
                ),
                Ok(()),
            ),
            (
                VC::new(
                    "test-1#213",
                    REVOCATION_LIST_2020_STATUS_TYPE,
                    "test-1123", // ERROR: id doesnt match
                    8743,
                ),
                Err(()),
            ),
            (
                VC::new(
                    "test-1#213",
                    REVOCATION_LIST_2020_STATUS_TYPE,
                    "https://example.rl/1",
                    200_000_000, // ERROR: index out of bound
                ),
                Err(()),
            ),
            (
                VC::new(
                    "test-1#213",
                    "diffenrntType", // ERROR: type doesnt match
                    "https://example.rl/1",
                    56_741,
                ),
                Err(()),
            ),
        ];

        // TODO: improve tests
        for (vc, outcome) in tests {
            let rr = rl.is_revoked(&vc);
            assert_eq!(rr.is_err(), outcome.is_err());
            if outcome.is_err() {
                continue;
            }
            assert_eq!(rr.unwrap(), false);

            let rr = rl.revoke(&vc);
            assert_eq!(rr.is_err(), outcome.is_err());

            let rr = rl.is_revoked(&vc);
            assert_eq!(rr.is_err(), outcome.is_err());
            assert_eq!(rr.unwrap(), true);

            let rr = rl.reset(&vc);
            assert_eq!(rr.is_err(), outcome.is_err());

            let rr = rl.is_revoked(&vc);
            assert_eq!(rr.is_err(), outcome.is_err());
            assert_eq!(rr.unwrap(), false);
        }
    }

    #[test]
    fn load_rl() {
        let data = r#"
        {
            "id": "test-1",
			"type": "RevocationList2020",
			"encodedList": "eJzswDEBAAAAwiD7pzbGHhgAAAAAAAAAAAAAAAAAAACQewAAAP//QAAAAQ=="
        }"#;
        // Parse the string of data into a Person object. This is exactly the
        // same function as the one that produced serde_json::Value above, but
        // now we are asking it for a Person as output.

        let rl = RevocationList2020::from_str(data);
        println!("{:?}", rl);
        assert_eq!(rl.is_err(), false);
        assert_eq!(
            rl.unwrap().encoded_list,
            "eJzswDEBAAAAwiD7pzbGHhgAAAAAAAAAAAAAAAAAAACQewAAAP//QAAAAQ=="
        )
    }
}

// WASM stuff

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleCredential {
    #[serde(rename = "credentialStatus")]
    credential_status: BasicCredentialStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicCredentialStatus {
    #[serde(rename = "revocationListIndex")]
    revocation_list_index: u64,
    #[serde(rename = "revocationListCredential")]
    revocation_list_credential: String,
}

/// To be able to use the rl2020 library it's neccessary
/// to implement the CredentialStatus trait
impl CredentialStatus for SimpleCredential {
    fn coordinates(&self) -> (String, u64) {
        (
            self.credential_status.revocation_list_credential.to_owned(),
            self.credential_status.revocation_list_index.to_owned(),
        )
    }

    fn type_def(&self) -> (String, String) {
        ("42".to_owned(), REVOCATION_LIST_2020_STATUS_TYPE.to_owned())
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn is_revoked(
    revocation_list_credential: &str,
    subject_credential: &str,
) -> Result<bool, JsValue> {
    let rl = RevocationList2020::from_str(revocation_list_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the revocation list: {}",
            err.to_string()
        ))
    })?;
    let cr = serde_json::from_str::<SimpleCredential>(subject_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the input credential: {}",
            err.to_string()
        ))
    })?;
    rl.is_revoked(&cr).map_err(|err| {
        JsValue::from(&format!(
            "error checking the revocation status: {}",
            err.to_string()
        ))
    })
}

#[wasm_bindgen]
pub fn revoke_credential(
    revocation_list_credential: &str,
    subject_credential: &str,
) -> Result<String, JsValue> {
    let mut rl = RevocationList2020::from_str(revocation_list_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the revocation list: {}",
            err.to_string()
        ))
    })?;
    let cr = serde_json::from_str::<SimpleCredential>(subject_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the input credential: {}",
            err.to_string()
        ))
    })?;
    rl.revoke(&cr).map_err(|err| {
        JsValue::from(&format!(
            "error checking the revocation status: {}",
            err.to_string()
        ))
    })?;
    Ok(rl.to_string())
}

#[wasm_bindgen]
pub fn reset_credential(
    revocation_list_credential: &str,
    subject_credential: &str,
) -> Result<String, JsValue> {
    let mut rl = RevocationList2020::from_str(revocation_list_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the revocation list: {}",
            err.to_string()
        ))
    })?;
    let cr = serde_json::from_str::<SimpleCredential>(subject_credential).map_err(|err| {
        JsValue::from(&format!(
            "error parsing the input credential: {}",
            err.to_string()
        ))
    })?;
    rl.reset(&cr).map_err(|err| {
        JsValue::from(&format!(
            "error checking the revocation status: {}",
            err.to_string()
        ))
    })?;
    Ok(rl.to_string())
}
