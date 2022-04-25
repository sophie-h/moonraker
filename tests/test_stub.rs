use moonraker::keyring;

use std::collections::HashMap;

async fn get_key() -> Result<keyring::api::Key, keyring::Error> {
    let keyring = keyring::api::Keyring::load(keyring::api::Keyring::default_path()?).await?;

    let secret = [
        44, 173, 251, 20, 203, 56, 241, 169, 91, 54, 51, 244, 40, 40, 202, 92, 71, 233, 174, 17,
        145, 58, 7, 107, 31, 204, 175, 245, 112, 174, 31, 198, 162, 149, 13, 127, 119, 113, 13, 3,
        191, 143, 162, 153, 183, 7, 21, 116, 81, 45, 51, 198, 73, 127, 147, 40, 52, 25, 181, 188,
        48, 159, 0, 146,
    ];

    Ok(keyring.derive_key(&secret))
}
#[async_std::test]
async fn keyfile_add_remove() -> keyring::api::Result<()> {
    let key = get_key().await?;

    let needle = HashMap::from([(String::from("key"), String::from("value"))]);

    let mut keyring = keyring::api::Keyring::new();

    keyring.items.push(
        keyring::Item::new(String::from("Label"), needle.clone(), b"MyPassword").encrypt(&key)?,
    );

    assert_eq!(keyring.search_items(needle.clone(), &key)?.len(), 1);

    keyring.remove_items(needle.clone(), &key)?;

    assert_eq!(keyring.search_items(needle, &key)?.len(), 0);

    Ok(())
}

#[async_std::test]
async fn keyfile_dump_load() {
    let key = get_key().await.unwrap();

    let _silent = std::fs::remove_file("/tmp/test.keyring");

    let mut new_keyring = keyring::api::Keyring::new();
    new_keyring.items.push(
        keyring::Item::new(
            String::from("My Label"),
            HashMap::from([(String::from("my-tag"), String::from("my tag value"))]),
            "A Password".as_bytes(),
        )
        .encrypt(&key)
        .unwrap(),
    );
    new_keyring.dump("/tmp/test.keyring", None).await.unwrap();

    let loaded_keyring = keyring::api::Keyring::load("/tmp/test.keyring")
        .await
        .unwrap();
    let loaded_items = loaded_keyring
        .search_items(HashMap::from([("my-tag", "my tag value")]), &key)
        .unwrap();

    assert_eq!(*loaded_items[0].password(), "A Password".as_bytes());

    let _silent = std::fs::remove_file("/tmp/test.keyring");
}
