use async_std::prelude::*;

use async_std::path::Path;
use cipher::{
    block_padding::Pkcs7, crypto_common::rand_core, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use hmac::Mac;
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

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

#[derive(Debug)]
pub enum Error {
    FileHeaderMismatch(Option<String>),
    VersionMismatch(Option<Vec<u8>>),
    NoData,
    GVariantDeserialization(zvariant::Error),
    Io(std::io::Error),
    MacError,
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

impl From<digest::MacError> for Error {
    fn from(_value: digest::MacError) -> Self {
        Self::MacError
    }
}

/// Logical contents of a keyring file
#[derive(Deserialize, Serialize, Type, Debug)]
pub struct Keyring {
    salt_size: u32,
    salt: Vec<u8>,
    pub iteration_count: u32,
    pub modified_time: u64,
    pub usage_count: u32,
    pub items: Vec<EncryptedItem>,
}

impl Keyring {
    pub async fn load_default() -> Result<Self, Error> {
        Self::load(&Self::default_path()).await
    }

    /// Load from a keyring file
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = async_std::fs::read(path).await?;
        Self::try_from(content.as_slice())
    }

    /// Write to a keyring file
    pub async fn dump<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        todo!()
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
        let header = value.get(..FILE_HEADER.len());
        if header != Some(FILE_HEADER) {
            return Err(Error::FileHeaderMismatch(
                header.map(|x| String::from_utf8_lossy(x).to_string()),
            ));
        }

        let version = value.get(FILE_HEADER_LEN..(FILE_HEADER_LEN + 2));
        if version != Some(&[MAJOR_VERSION, MINOR_VERSION]) {
            return Err(Error::VersionMismatch(version.map(|x| x.to_vec())));
        }

        if let Some(data) = value.get((FILE_HEADER_LEN + 2)..) {
            Ok(zvariant::from_slice(data, gvariant_encoding())?)
        } else {
            Err(Error::NoData)
        }
    }
}

#[derive(Deserialize, Serialize, Type, Debug)]
pub struct EncryptedItem {
    pub hashed_attributes: HashMap<String, Vec<u8>>,
    pub blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn decrypt(mut self, key: &[u8]) -> Result<Item, Error> {
        let mac_tag = self.blob.split_off(self.blob.len() - MAC_SIZE);

        // verify item
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(&self.blob);
        mac.verify_slice(&mac_tag)?;

        let iv = self.blob.split_off(self.blob.len() - IV_SIZE);
        let mut data = Zeroizing::new(self.blob);

        // decrypt item
        let decrypted = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .unwrap();

        Item::try_from(decrypted)
    }
}

#[derive(Deserialize, Serialize, Type, Debug, Zeroize)]
pub struct Item {
    // TODO: Zeroize the values
    #[zeroize(skip)]
    attributes: HashMap<String, String>,
    label: String,
    created: u64,
    modified: u64,
    password: Vec<u8>,
}

impl Item {
    pub fn encrypt(self, key: &[u8]) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(gvariant_encoding(), &self)?);

        let iv = cbc::Encryptor::<aes::Aes128>::generate_iv(rand_core::OsRng);

        let mut blob = vec![0; decrypted.len() + CIPHER_BLOCK_SIZE];

        // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for PKCS7
        let encrypted_len = cbc::Encryptor::<aes::Aes128>::new(key.into(), &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(&decrypted, &mut blob)
            .unwrap()
            .len();

        blob.truncate(encrypted_len);
        blob.append(&mut iv.as_slice().into());

        // Unwrapping since arbitrary keylength allowed
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(&blob);
        blob.append(&mut mac.finalize().into_bytes().as_slice().into());

        // TODO: write hashed attributes
        let hashed_attributes = Default::default();

        Ok(EncryptedItem {
            hashed_attributes,
            blob,
        })
    }
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
