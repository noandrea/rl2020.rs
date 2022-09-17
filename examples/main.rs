use rl2020::{CredentialStatus, RevocationList2020};
use serde_derive::{Deserialize, Serialize};

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

fn main() {
    println!("Hello, RevocationList2020!");

    // create a new revocation list
    let mut rl = RevocationList2020::new("https://example.com/credentials/status/3", 16).unwrap();
    println!("{}", rl);

    // create a credential that uses the revocation list
    let c = create_credential();

    let revoked = rl.is_revoked(&c).unwrap();
    println!(
        "credential with id {} is revoked? {}",
        c.credential_status.revocation_list_index, revoked
    ); // prints false

    println!(
        "revoking credential with index {}",
        c.credential_status.revocation_list_index
    );
    rl.revoke(&c).unwrap();
    let revoked = rl.is_revoked(&c).unwrap();
    println!("{}", rl);

    println!(
        "credential with id {} is revoked? {}",
        c.credential_status.revocation_list_index, revoked
    ); // prints true

    println!(
        "resetting status for credential with index {}",
        c.credential_status.revocation_list_index
    );

    rl.reset(&c).unwrap();
    let revoked = rl.is_revoked(&c).unwrap();
    println!("{}", rl);

    println!(
        "credential with id {} is revoked? {}",
        c.credential_status.revocation_list_index, revoked
    ); // prints false
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
