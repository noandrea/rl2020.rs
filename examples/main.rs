use rl2020::RevocationList2020;

fn main() {
    println!("Hello, RevocationList2020!");

    let mut rl = RevocationList2020::new("test-1", 16).unwrap();

    rl.revoke(1).unwrap();
    rl.revoke(10).unwrap();
    rl.revoke(100).unwrap();
    rl.revoke(1000).unwrap();

    let credential_index = 34567;
    let revoked = rl.is_revoked(credential_index).unwrap();
    println!(
        "credential with id {} is revoked? {}",
        credential_index, revoked
    ); // prints false

    rl.revoke(credential_index).unwrap();
    let revoked = rl.is_revoked(credential_index).unwrap();

    println!(
        "credential with id {} is revoked? {}",
        credential_index, revoked
    ); // prints true

    rl.reset(credential_index).unwrap();
    let revoked = rl.is_revoked(credential_index).unwrap();

    println!(
        "credential with id {} is revoked? {}",
        credential_index, revoked
    ); // prints false
}
