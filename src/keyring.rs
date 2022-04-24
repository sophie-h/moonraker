use async_std::prelude::*;

use async_std::path::Path;
use cbc::cipher::BlockDecryptMut;
use cbc::cipher::{block_padding::Pkcs7, KeyIvInit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};
use zvariant::Type;

//const SALT_SIZE: usize = 32;
//const ITERATION_COUNT: usize = 100000;

//const MAC_ALGO = GCRY_MAC_HMAC_SHA256;
const MAC_SIZE: usize = 32;

//const CIPHER_ALGO = GCRY_CIPHER_AES256;
const CIPHER_BLOCK_SIZE: usize = 16;
const IV_SIZE: usize = CIPHER_BLOCK_SIZE;

const KEYRING_FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const KEYRING_FILE_HEADER_LEN: usize = KEYRING_FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

#[derive(Debug)]
pub enum Error {
    FileHeaderMismatch(Option<String>),
    VersionMismatch(Option<Vec<u8>>),
    NoData,
    GVariantDeserialization(zvariant::Error),
    Io(std::io::Error),
}

impl From<zvariant::Error> for Error {
    fn from(value: zvariant::Error) -> Self {
        Self::GVariantDeserialization(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Deserialize, Serialize, Type, Debug)]
pub struct Keyring {
    pub salt_size: u32,
    pub salt: Vec<u8>,
    pub iteration_count: u32,
    pub modified_time: u64,
    pub usage_count: u32,
    pub items: Vec<ItemEncrypted>,
}

impl Keyring {
    pub async fn load_default() -> Result<Self, Error> {
        Self::load(&Self::default_path()).await
    }

    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = async_std::fs::read(path).await?;
        Self::try_from(content.as_slice())
    }

    // TODO: This adds glib dependency
    pub fn default_path() -> PathBuf {
        let mut path = glib::user_data_dir();
        path.push("keyrings");
        path.push("default.keyring");

        dbg!(path)
    }

    pub fn derive_key(&self, secret: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut key = Zeroizing::new(vec![0; CIPHER_BLOCK_SIZE]);

        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            secret,
            &self.salt,
            self.iteration_count,
            &mut key,
        );

        key
    }
}

impl TryFrom<&[u8]> for Keyring {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let header = value.get(..KEYRING_FILE_HEADER.len());
        if header != Some(KEYRING_FILE_HEADER) {
            return Err(Error::FileHeaderMismatch(
                header.map(|x| String::from_utf8_lossy(x).to_string()),
            ));
        }

        let version = value.get(KEYRING_FILE_HEADER_LEN..(KEYRING_FILE_HEADER_LEN + 2));
        if version != Some(&[MAJOR_VERSION, MINOR_VERSION]) {
            return Err(Error::VersionMismatch(version.map(|x| x.to_vec())));
        }

        if let Some(data) = value.get((KEYRING_FILE_HEADER_LEN + 2)..) {
            Ok(zvariant::from_slice(data, gvariant_encoding())?)
        } else {
            Err(Error::NoData)
        }
    }
}

#[derive(Deserialize, Serialize, Type, Debug)]
pub struct ItemEncrypted {
    pub attributes_hashed: HashMap<String, Vec<u8>>,
    pub blob: Vec<u8>,
}

impl ItemEncrypted {
    pub fn decrypt(mut self, key: &[u8]) -> Result<Item, Error> {
        let _mac = self.blob.split_off(self.blob.len() - MAC_SIZE);
        let iv = self.blob.split_off(self.blob.len() - IV_SIZE);
        let mut data = Zeroizing::new(self.blob);

        let decrypted = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .unwrap();

        Item::try_from(decrypted)
    }
}

#[derive(Deserialize, Serialize, Type, Debug, Zeroize)]
pub struct Item {
    // TODO: Ideally zeroize this as well
    #[zeroize(skip)]
    attributes: HashMap<String, String>,
    label: String,
    created: u64,
    modified: u64,
    password: Vec<u8>,
}

impl TryFrom<&[u8]> for Item {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(zvariant::from_slice(value, gvariant_encoding())?)
    }
}

pub fn gvariant_encoding() -> zvariant::EncodingContext<byteorder::LE> {
    zvariant::EncodingContext::<byteorder::LE>::new_gvariant(0)
}

// TODO: Do we actually want to pull ashpd as depencdency?
async fn secret() -> Result<Vec<u8>, ashpd::Error> {
    let connection = zbus::Connection::session().await?;
    let proxy = ashpd::desktop::secret::SecretProxy::new(&connection).await?;

    let (mut x1, x2) = async_std::os::unix::net::UnixStream::pair().unwrap();

    dbg!(proxy.retrieve_secret(&x2).await.unwrap());
    drop(x2);
    let mut buf = Vec::new();
    x1.read_to_end(&mut buf).await.unwrap();

    dbg!(buf.len());

    Ok(buf)
}
