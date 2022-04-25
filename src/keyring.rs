use async_std::path::Path;
use cipher::{
    block_padding::Pkcs7, crypto_common::rand_core, BlockDecryptMut, BlockEncryptMut,
    BlockSizeUser, IvSizeUser, KeyIvInit,
};
use digest::OutputSizeUser;
use hmac::Mac;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};
use zvariant::Type;

const SALT_SIZE: usize = 32;
const ITERATION_COUNT: u32 = 100000;

const FILE_HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";
const FILE_HEADER_LEN: usize = FILE_HEADER.len();

const MAJOR_VERSION: u8 = 1;
const MINOR_VERSION: u8 = 0;

type MacAlg = hmac::Hmac<sha2::Sha256>;
type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

#[derive(Debug)]
pub enum Error {
    FileHeaderMismatch(Option<String>),
    VersionMismatch(Option<Vec<u8>>),
    NoData,
    NoParentDir(String),
    GVariantDeserialization(zvariant::Error),
    Io(std::io::Error),
    MacError,
    HashedAttributeMac(String),
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
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>().to_vec();

        Self {
            salt_size: salt.len() as u32,
            salt,
            iteration_count: ITERATION_COUNT,
            // TODO: UTC?
            modified_time: std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .unwrap()
                .as_secs(),
            usage_count: 0,
            items: Vec::new(),
        }
    }

    pub async fn load_default() -> Result<Self, Error> {
        Self::load(&Self::default_path()).await
    }

    /// Load from a keyring file
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = async_std::fs::read(path).await?;
        Self::try_from(content.as_slice())
    }

    /// Write to a keyring file
    pub async fn dump<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut tmpfile = if let Some(parent) = path.as_ref().parent() {
            Ok(tempfile::NamedTempFile::new_in(parent)?)
        } else {
            Err(Error::NoParentDir(path.as_ref().display().to_string()))
        }?;

        let blob: Vec<u8> = self.as_bytes()?;

        use std::io::Write;
        // TODO: this is currently blocking
        // We need a solution for race conditions
        tmpfile.write_all(&blob)?;
        tmpfile.persist(path.as_ref()).unwrap();

        Ok(())
    }

    pub fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
        key: &[u8],
    ) -> Result<Vec<Item>, Error> {
        let hashed_search: Vec<(&str, Vec<u8>)> = attributes
            .into_iter()
            .map(|(k, v)| {
                (k, {
                    let mut mac = MacAlg::new_from_slice(key).unwrap();
                    mac.update(v.as_bytes());
                    mac.finalize().into_bytes().as_slice().to_vec()
                })
            })
            .collect();

        // TODO: we could make them constant time comparisons
        self.items
            .iter()
            .filter(|e| {
                hashed_search.iter().all(|(search_key, search_hash)| {
                    e.hashed_attributes.get(*search_key) == Some(search_hash)
                })
            })
            .map(|e| (*e).clone().decrypt(key))
            .collect()
    }

    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut blob = FILE_HEADER.to_vec();

        blob.push(MAJOR_VERSION);
        blob.push(MINOR_VERSION);
        blob.append(&mut zvariant::to_bytes(gvariant_encoding(), &self)?);

        Ok(blob)
    }

    // TODO: This adds glib dependency
    pub fn default_path() -> PathBuf {
        let mut path = glib::user_data_dir();
        path.push("keyrings");
        path.push("default.keyring");

        path
    }

    pub fn derive_key(&self, secret: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut key = Zeroizing::new(vec![0; EncAlg::block_size()]);

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

#[derive(Deserialize, Serialize, Type, Debug, Clone)]
pub struct EncryptedItem {
    pub hashed_attributes: HashMap<String, Vec<u8>>,
    pub blob: Vec<u8>,
}

impl EncryptedItem {
    pub fn decrypt(mut self, key: &[u8]) -> Result<Item, Error> {
        let mac_tag = self
            .blob
            .split_off(self.blob.len() - hmac::HmacCore::<sha2::Sha256>::output_size());

        // verify item
        let mut mac = MacAlg::new_from_slice(key).unwrap();
        mac.update(&self.blob);
        mac.verify_slice(&mac_tag)?;

        let iv = self.blob.split_off(self.blob.len() - DecAlg::iv_size());
        let mut data = Zeroizing::new(self.blob);

        // decrypt item
        let decrypted = DecAlg::new(key.into(), iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .unwrap();

        let item = Item::try_from(decrypted)?;

        Self::validate(&self.hashed_attributes, &item, key)?;

        Ok(item)
    }

    fn validate(
        hashed_attributes: &HashMap<String, Vec<u8>>,
        item: &Item,
        key: &[u8],
    ) -> Result<(), Error> {
        for (attribute_key, hashed_attribute) in hashed_attributes.iter() {
            if let Some(attribute_plaintext) = item.attributes.get(attribute_key) {
                let mut mac = MacAlg::new_from_slice(key).unwrap();
                mac.update(attribute_plaintext.as_bytes());
                if mac.verify_slice(hashed_attribute).is_err() {
                    return Err(Error::HashedAttributeMac(attribute_key.to_string()));
                }
            } else {
                return Err(Error::HashedAttributeMac(attribute_key.to_string()));
            }
        }

        Ok(())
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
    pub password: Vec<u8>,
}

impl Item {
    pub fn new<P: AsRef<[u8]>>(
        label: String,
        attributes: HashMap<String, String>,
        password: P,
    ) -> Self {
        let now = std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_secs();

        Item {
            attributes,
            label,
            created: now,
            modified: now,
            password: password.as_ref().to_vec(),
        }
    }

    pub fn encrypt(self, key: &[u8]) -> Result<EncryptedItem, Error> {
        let decrypted = Zeroizing::new(zvariant::to_bytes(gvariant_encoding(), &self)?);

        let iv = EncAlg::generate_iv(rand_core::OsRng);

        let mut blob = vec![0; decrypted.len() + EncAlg::block_size()];

        // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for PKCS7
        let encrypted_len = EncAlg::new(key.into(), &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(&decrypted, &mut blob)
            .unwrap()
            .len();

        blob.truncate(encrypted_len);
        blob.append(&mut iv.as_slice().into());

        // Unwrapping since arbitrary keylength allowed
        let mut mac = MacAlg::new_from_slice(key).unwrap();
        mac.update(&blob);
        blob.append(&mut mac.finalize().into_bytes().as_slice().into());

        // TODO: write hashed attributes
        let hashed_attributes = self
            .attributes
            .into_iter()
            .map(|(k, v)| {
                (k, {
                    let mut mac = MacAlg::new_from_slice(key).unwrap();
                    mac.update(v.as_bytes());
                    mac.finalize().into_bytes().as_slice().to_vec()
                })
            })
            .collect();

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

// TODO: use our implementation
/*
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
*/
