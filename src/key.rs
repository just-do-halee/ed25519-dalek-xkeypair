// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

use super::errors::*;
use super::private::*;
use super::types::*;

use hmac::{Hmac, Mac, NewMac};
use ripemd160::{Digest, Ripemd160};
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const ED25519_DOMAIN_NAME: &str = "ed25519 seed";
pub const SEED_SIZE_LIST: &[usize] = &[16, 32, 64];

/// simply represented by `extended secret key`
#[derive(Debug)]
pub struct ExtendedKeypair {
    prefix: ExtPrefix,
    attrs: ExtAttributes,
    pair: DalekKeypair,
}

impl PartialEq for ExtendedKeypair {
    fn eq(&self, other: &Self) -> bool {
        (self.prefix == other.prefix)
            && (self.attrs == other.attrs)
            && (self.pair.secret.as_bytes() == other.pair.secret.as_bytes())
            && (self.pair.public.as_bytes() == other.pair.public.as_bytes())
    }
}
impl Eq for ExtendedKeypair {}

impl ExtendedKeypair {
    /// 78 (extended secret key)
    pub const LENGTH: usize = consts::TOTAL_LENGTH;
    pub const BASE58MAX_LENGTH: usize = 112;

    pub fn prefix(&self) -> &ExtPrefix {
        &self.prefix
    }
    pub fn attrs(&self) -> &ExtAttributes {
        &self.attrs
    }
    pub fn pair(&self) -> &DalekKeypair {
        &self.pair
    }

    pub fn secret_to_hex(&self) -> String {
        hex::encode(&self.pair.secret)
    }
    pub fn public_to_hex(&self) -> String {
        hex::encode(&self.pair.public)
    }
    pub fn chaincode_to_hex(&self) -> String {
        hex::encode(&self.attrs.chain_code)
    }
    /// base58check(`extended secret key`)
    pub fn to_base58check(&self) -> String {
        bs58::encode(&self.to_bytes()).with_check().into_string()
    }

    pub fn dalekpair_from_secret_bytes(bytes: &[u8]) -> Result<DalekKeypair> {
        let bytes = match bytes.len() {
            consts::KEY_LENGTH => bytes,
            consts::EXTKEY_LENGTH => &bytes[1..],
            _ => {
                return errbang!(
                    err::InvalidLenSize,
                    "{}, must be {} or {}.",
                    bytes.len(),
                    consts::KEY_LENGTH,
                    consts::EXTKEY_LENGTH
                )
            }
        };
        let secret = errcast!(SecretKey::from_bytes(bytes), err::Parser);
        let public = PublicKey::from(&secret);
        Ok(DalekKeypair { secret, public })
    }

    #[inline(always)]
    fn convert_to_bytes(xkey: &Self) -> [u8; Self::LENGTH] {
        let mut bytes = [0u8; Self::LENGTH];
        for (src, dst) in bytes.iter_mut().zip(
            xkey.prefix.to_bytes().iter().chain(
                xkey.attrs
                    .to_bytes()
                    .iter()
                    .chain([0u8].iter().chain(xkey.pair.secret.as_bytes().iter())),
            ),
        ) {
            *src = *dst;
        }
        bytes
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        Self::convert_to_bytes(self)
    }
    #[inline(always)]
    pub fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LENGTH {
            return errbang!(
                err::InvalidLenSize,
                "{}, must be {}.",
                bytes.len(),
                Self::LENGTH
            );
        }
        let prefix = ExtPrefix::from_bytes(&bytes[..ExtPrefix::LENGTH])?;
        let attrs_end_len = ExtPrefix::LENGTH + ExtAttributes::LENGTH;
        let attrs = ExtAttributes::from_bytes(&bytes[ExtPrefix::LENGTH..attrs_end_len])?;
        let pair = Self::dalekpair_from_secret_bytes(&bytes[attrs_end_len..])?;
        Ok(Self {
            prefix,
            attrs,
            pair,
        })
    }

    /// base58check(`extended secret key`)
    pub fn write_base58check<'a>(
        &self,
        output: &'a mut [u8; Self::BASE58MAX_LENGTH],
    ) -> Result<&'a str> {
        let mut buf = Self::convert_to_bytes(self);
        let base58_len = errcast!(
            bs58::encode(&buf).with_check().into(output.as_mut()),
            err::Parser
        );
        buf.zeroize();

        Ok(errcast!(str::from_utf8(&output[..base58_len]), err::Parser))
    }

    pub fn from_seed_with_domain(
        domain_name: &str,
        seed: &[u8],
        prefix: ExtPrefix,
    ) -> Result<Self> {
        if !SEED_SIZE_LIST.contains(&seed.len()) {
            return errbang!(
                err::InvalidLenSize,
                "{}, must be included in {:?}",
                seed.len(),
                SEED_SIZE_LIST
            );
        }
        let mut mac = errcast!(HmacSha512::new_from_slice(domain_name.as_ref()), err::Hmac);

        mac.update(seed);
        let bytes = mac.finalize().into_bytes();

        let (child_key, chain_code) = bytes.split_at(consts::KEY_LENGTH);

        let pair = Self::dalekpair_from_secret_bytes(child_key)?;
        let attrs = {
            let depth = 0;
            let parent_fingerprint = ParentFingerprint::default();
            let child_index = ChildIndex::Normal(0);
            let chain_code = chain_code.try_into().unwrap();
            ExtAttributes {
                depth,
                parent_fingerprint,
                child_index,
                chain_code,
            }
        };

        Ok(Self {
            prefix,
            attrs,
            pair,
        })
    }

    #[inline(always)]
    pub fn from_seed(seed: &[u8], prefix: ExtPrefix) -> Result<Self> {
        Self::from_seed_with_domain(ED25519_DOMAIN_NAME, seed, prefix)
    }

    pub fn derive<P: AsRef<[ChildIndex]>>(&self, path: &P) -> Result<Self> {
        let mut path = path.as_ref().iter();
        let mut next = match path.next() {
            Some(index) if index.is_hardened() => self.derive_child(index.to_u32())?,
            Some(_) => return errbang!(err::Parser, "must be hardened index only."),
            None => self.clone(),
        };
        for index in path {
            if index.is_hardened() {
                next = next.derive_child(index.to_u32())?;
            } else {
                return errbang!(err::Parser, "must be hardened index only.");
            }
        }
        Ok(next)
    }

    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let depth = match self.attrs.depth.checked_add(1) {
            Some(v) => v,
            None => return errbang!(err::Overflow),
        };

        let mut mac = errcast!(
            HmacSha512::new_from_slice(&self.attrs.chain_code),
            err::Hmac
        );

        mac.update(&[0u8]);
        mac.update(self.pair.secret.as_bytes());
        mac.update(&ChildIndex::Hardened(index).to_bits().to_be_bytes());
        let bytes = mac.finalize().into_bytes();

        let (child_key, chain_code) = bytes.split_at(consts::KEY_LENGTH);

        let pair = Self::dalekpair_from_secret_bytes(child_key)?;
        let attrs = {
            let parent_fingerprint = Ripemd160::digest(&Sha256::digest(pair.public.as_bytes()))
                [..4]
                .try_into()
                .unwrap();
            let child_index = ChildIndex::Hardened(index);
            let chain_code = chain_code.try_into().unwrap();
            ExtAttributes {
                depth,
                parent_fingerprint,
                child_index,
                chain_code,
            }
        };

        Ok(Self {
            prefix: self.prefix,
            attrs,
            pair,
        })
    }
}

impl Clone for ExtendedKeypair {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            prefix: self.prefix,
            attrs: self.attrs.clone(),
            pair: DalekKeypair {
                secret: SecretKey::from_bytes(self.pair.secret.as_bytes()).unwrap(),
                public: self.pair.public,
            },
        }
    }
}

impl Display for ExtendedKeypair {
    // + to_string()
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; Self::BASE58MAX_LENGTH];
        self.write_base58check(&mut buf)
            .map_err(|_| fmt::Error)
            .and_then(|base58| f.write_str(base58))
    }
}

impl FromStr for ExtendedKeypair {
    type Err = Error;
    fn from_str(base58check: &str) -> Result<Self> {
        let mut bytes = [0u8; Self::LENGTH + consts::CHECKSUM_LENGTH];
        let decoded_len = errcast!(
            bs58::decode(base58check).with_check(None).into(&mut bytes),
            err::Parser
        );

        if decoded_len != Self::LENGTH {
            return errbang!(err::Parser);
        }

        let out = Self::from_bytes(&bytes[..Self::LENGTH])?;
        bytes.zeroize();
        Ok(out)
    }
}
