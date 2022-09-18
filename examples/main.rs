use rl2020::{CredentialError, CredentialStatus, RevocationList2020};
use serde_derive::{Deserialize, Serialize};

fn main() -> Result<(), CredentialError> {
    println!("Hello, RevocationList2020!");

    // create a new revocation list
    let mut rl = RevocationList2020::new("https://example.com/credentials/status/3", 16)?;
    println!("{}", rl);

    // create a credential that uses the revocation list
    let c = create_credential();
    let c_idx = c.credential_status.revocation_list_index;

    // check if the credential is revoked
    let revoked = rl.is_revoked(&c)?;
    println!("credential at index {} is revoked? {}", c_idx, revoked);
    // revoke the credential
    println!("revoking credential at index {}", c_idx);
    rl.revoke(&c)?;
    // print the updated revocation list
    println!("{}", rl);
    //check if the credential is revoked
    let revoked = rl.is_revoked(&c)?;
    println!("credential at index {} is revoked? {}", c_idx, revoked);
    // reset the credential revocation
    println!("resetting status for credential at index {}", c_idx);
    rl.reset(&c)?;
    // print the updated revocation list
    println!("{}", rl);
    //check if the credential is revoked
    let revoked = rl.is_revoked(&c)?;
    println!("credential at index {} is revoked? {}", c_idx, revoked);

    Ok(())
}

fn create_credential() -> VerifableCredential {
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
    serde_json::from_str::<VerifableCredential>(data).unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifableCredential {
    #[serde(rename = "credentialStatus")]
    credential_status: CredentialStatusExample,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatusExample {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "type")]
    typ: String,
    #[serde(rename = "revocationListIndex")]
    revocation_list_index: u64,
    #[serde(rename = "revocationListCredential")]
    revocation_list_credential: String,
}

/// To be able to use the rl2020 library it's neccessary
/// to implement the CredentialStatus trait
impl CredentialStatus for VerifableCredential {
    fn coordinates(&self) -> (String, u64) {
        (
            self.credential_status.revocation_list_credential.to_owned(),
            self.credential_status.revocation_list_index.to_owned(),
        )
    }

    fn type_def(&self) -> (String, String) {
        (
            self.credential_status.id.to_owned(),
            self.credential_status.typ.to_owned(),
        )
    }
}
