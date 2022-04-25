use moonraker::keyring;

use std::collections::HashMap;

/*
fn main() {
    println!("Hello, world!");
    //x();
    async_std::task::block_on(decrypt_new()).unwrap();
}
*/

async fn get_key() -> Result<zeroize::Zeroizing<Vec<u8>>, keyring::Error> {
    let keyring = keyring::Keyring::load_default().await?;

    let secret = [
        44, 173, 251, 20, 203, 56, 241, 169, 91, 54, 51, 244, 40, 40, 202, 92, 71, 233, 174, 17,
        145, 58, 7, 107, 31, 204, 175, 245, 112, 174, 31, 198, 162, 149, 13, 127, 119, 113, 13, 3,
        191, 143, 162, 153, 183, 7, 21, 116, 81, 45, 51, 198, 73, 127, 147, 40, 52, 25, 181, 188,
        48, 159, 0, 146,
    ];

    Ok(keyring.derive_key(&secret))
}

#[async_std::test]
async fn test_collection() -> Result<(), keyring::Error> {
    let key = get_key().await?;

    let keyring = keyring::Keyring::load_default().await?;

    for item_encrypted in &keyring.items {
        let item = item_encrypted.clone().decrypt(&key).unwrap();
        dbg!(&item);
        let item_encrypted_2 = item.encrypt(&key).unwrap();
        let item2 = item_encrypted_2.decrypt(&key).unwrap();
        dbg!(&item2);
    }

    dbg!(keyring
        .search_items(HashMap::from([("tag-name", "some-value")]), &key)
        .unwrap());
    dbg!(keyring
        .search_items(HashMap::from([("tag-namex", "some-value")]), &key)
        .unwrap());

    Ok(())
}

#[async_std::test]
async fn test_dump_load() {
    let key = get_key().await.unwrap();

    let mut new_keyring = keyring::Keyring::new();
    new_keyring.items.push(
        keyring::Item::new(
            String::from("My Label"),
            HashMap::from([(String::from("my-tag"), String::from("my tag value"))]),
            "A Password".as_bytes(),
        )
        .encrypt(&key)
        .unwrap(),
    );
    new_keyring.dump("/tmp/test.keyring").await.unwrap();

    let loaded_keyring = keyring::Keyring::load("/tmp/test.keyring").await.unwrap();
    let loaded_items = loaded_keyring
        .search_items(HashMap::from([("my-tag", "my tag value")]), &key)
        .unwrap();

    assert_eq!(*loaded_items[0].password(), "A Password".as_bytes());
}

/*
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
*/
