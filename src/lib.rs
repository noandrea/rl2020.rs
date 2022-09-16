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
// Minimum bitstring size is 16kb
const MIN_BITSTRING_SIZE_KN: usize = 16;
// Maximum bistsring size is 128kb
const MAX_BITSTRING_SIZE_KB: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    #[serde(rename = "credentialStatus")]
    credential_status: CredentialStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(rename = "revocationListIndex")]
    revocation_list_index: u32,
    #[serde(rename = "revocationListCredential")]
    revocation_list_credential: String,
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
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
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

    pub fn revoke(&mut self, index: u64) -> Result<(), CredentialError> {
        self.update(RevocationStatus::Revoke, index)
    }

    pub fn reset(&mut self, index: u64) -> Result<(), CredentialError> {
        self.update(RevocationStatus::Reset, index)
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

    pub fn is_revoked(&self, index: u64) -> Result<bool, CredentialError> {
        self.get(index).map(|x| match x {
            RevocationStatus::Revoke => true,
            RevocationStatus::Reset => false,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{Credential, RevocationList2020, RevocationStatus};
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
            let rev = rl.is_revoked(credential_index);
            assert_eq!(rev.is_err(), false);
            let rev = rev.unwrap();
            assert_eq!(rev, true);

            let up = rl.update(RevocationStatus::Reset, credential_index);
            assert_eq!(up.is_err(), false);

            let get = rl.get(credential_index);
            assert_eq!(get.is_err(), false);
            let get = get.unwrap();
            assert_eq!(get, RevocationStatus::Reset);
            let rev = rl.is_revoked(credential_index);
            assert_eq!(rev.is_err(), false);
            let rev = rev.unwrap();
            assert_eq!(rev, false);
        }

        println!("{}", rl);
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

    #[test]
    fn load_credential() {
        // Some JSON input data as a &str. Maybe this comes from the user.
        let data = r#"
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc-revocation-list-2020/v1"
            ],
            "id": "https://example.com/credentials/23894672394",
            "type": [
                "VerifiableCredential"
            ],
            "issuer": "did:example:12345",
            "issued": "2020-04-05T14:27:42Z",
            "credentialStatus": {
                "id": "https://dmv.example.gov/credentials/status/3#7812",
                "type": "RevocationList2020Status",
                "revocationListIndex": 7812,
                "revocationListCredential": "https://example.com/credentials/status/3"
            },
            "credentialSubject": {
                "id": "did:example:abcdefg",
                "type": "Person"
            },
            "proof": {}
        }"#;
        // Parse the string of data into a Person object. This is exactly the
        // same function as the one that produced serde_json::Value above, but
        // now we are asking it for a Person as output.
        match serde_json::from_str::<Credential>(data) {
            Ok(c) => {
                assert_eq!(c.credential_status.revocation_list_index, 7812);
            }
            Err(e) => {
                println!("{}", e);
                assert_eq!(1, 2)
            }
        }

        // Do things just like with any other Rust data structure.
    }
}
