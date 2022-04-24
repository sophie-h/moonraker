mod keyring;

use std::collections::HashMap;

fn main() {
    println!("Hello, world!");
    //x();
    async_std::task::block_on(decrypt_new()).unwrap();
}

async fn decrypt_new() -> Result<(), keyring::Error> {
    let keyring = keyring::Keyring::load_default().await?;

    let secret = [
        44, 173, 251, 20, 203, 56, 241, 169, 91, 54, 51, 244, 40, 40, 202, 92, 71, 233, 174, 17,
        145, 58, 7, 107, 31, 204, 175, 245, 112, 174, 31, 198, 162, 149, 13, 127, 119, 113, 13, 3,
        191, 143, 162, 153, 183, 7, 21, 116, 81, 45, 51, 198, 73, 127, 147, 40, 52, 25, 181, 188,
        48, 159, 0, 146,
    ];

    let key = keyring.derive_key(&secret);

    for item_encrypted in keyring.items {
        let item = item_encrypted.decrypt(&key);
        dbg!(item.unwrap());
    }

    Ok(())
}

fn x() {
    libsecret::password_store_sync(
        Some(&my_schema()),
        HashMap::from([("tag-name", "some-value")]),
        None,
        "My Text",
        "MySecretPassword",
        gio::Cancellable::NONE,
    )
    .unwrap();
}

fn my_schema() -> libsecret::Schema {
    libsecret::Schema::new(
        "org.example.moonraker",
        libsecret::SchemaFlags::NONE,
        HashMap::from([("tag-name", libsecret::SchemaAttributeType::String)]),
    )
}
