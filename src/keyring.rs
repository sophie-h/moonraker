/*!
Keyring

*/

pub mod api;
pub use api::{Error, Item, Result};

use async_std::prelude::*;

use async_std::path::{Path, PathBuf};
use async_std::{fs, io};
use std::collections::HashMap;

pub async fn lookup(attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
    let storage = Storage::load_default().await?;
    storage.keyring.search_items(attributes, &storage.key)
}

pub struct Storage {
    keyring: api::Keyring,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Option<std::time::SystemTime>,
    key: api::Key,
}

impl Storage {
    /// Load from default keyring file
    pub async fn load_default() -> Result<Self> {
        // TODO: use secret api here
        let secret = vec![1, 2];
        Self::load(api::Keyring::default_path()?, &secret).await
    }

    /// Load from a keyring file
    pub async fn load(path: impl AsRef<Path>, secret: &[u8]) -> Result<Self> {
        let (mtime, keyring) = match fs::File::open(&path).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => (None, api::Keyring::new()),
            Err(err) => return Err(err.into()),
            Ok(mut file) => {
                let mtime = file.metadata().await?.modified().ok();

                let mut content = Vec::new();
                file.read_to_end(&mut content).await?;

                let keyring = api::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        let key = keyring.derive_key(secret);

        Ok(Storage {
            keyring,
            path: path.as_ref().to_path_buf(),
            mtime,
            key,
        })
    }

    pub async fn write(self) -> Result<()> {
        self.keyring.dump(self.path, self.mtime).await
    }
}
