// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

use super::errors::*;
use super::private::*;
use zeroize::Zeroize;

pub use ed25519_dalek::{Keypair as DalekKeypair, PublicKey, SecretKey};

pub mod consts {
    /// 4
    pub const CHECKSUM_LENGTH: usize = 4;
    /// 78
    pub const TOTAL_LENGTH: usize =
        super::ExtPrefix::LENGTH + super::ExtAttributes::LENGTH + EXTKEY_LENGTH;

    /// 4
    pub const PREFIX_LENGTH: usize = 4;
    /// 32
    pub const KEY_LENGTH: usize = 32;
    /// 33
    pub const EXTKEY_LENGTH: usize = 33;
    /// 1
    pub const DEPTH_LENGTH: usize = 1;
    /// 4
    pub const FINGERPRINT_LENGTH: usize = 4;
    /// 4
    pub const CHILDINDEX_LENGTH: usize = 4;
    /// 32
    pub const CHAINCODE_LENGTH: usize = 32;
}

pub type Depth = u8;
pub type ParentFingerprint = [u8; consts::FINGERPRINT_LENGTH];
pub use derivation_path::ChildIndex;
pub type ChainCode = [u8; consts::CHAINCODE_LENGTH];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtAttributes {
    pub depth: Depth,
    pub parent_fingerprint: ParentFingerprint,
    pub child_index: ChildIndex,
    pub chain_code: ChainCode,
}

impl ExtAttributes {
    /// 41
    pub const LENGTH: usize = consts::DEPTH_LENGTH
        + consts::FINGERPRINT_LENGTH
        + consts::CHILDINDEX_LENGTH
        + consts::CHAINCODE_LENGTH;

    pub const LENGTH_WITHOUT_CHAINCODE: usize = Self::LENGTH - consts::CHAINCODE_LENGTH;

    /// depth: `u8`, parent_fingerprint: `[u8; 4]`, child_index: `ChildIndex`, chain_code: `[u8; 32]`
    pub fn new(
        depth: Depth,
        parent_fingerprint: ParentFingerprint,
        child_index: ChildIndex,
        chain_code: ChainCode,
    ) -> Self {
        Self {
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
        }
    }

    pub fn master(chain_code: ChainCode) -> Self {
        Self {
            depth: 0,
            parent_fingerprint: [0u8; consts::FINGERPRINT_LENGTH],
            child_index: ChildIndex::Normal(0),
            chain_code,
        }
    }

    /// this cannot be restored back to the form of 'from_bytes'
    #[inline]
    pub fn to_bytes_without_chaincode(&self) -> [u8; Self::LENGTH_WITHOUT_CHAINCODE] {
        let mut bytes = [0u8; Self::LENGTH_WITHOUT_CHAINCODE];
        for (src, dst) in bytes.iter_mut().zip(
            [self.depth].iter().chain(
                self.parent_fingerprint
                    .iter()
                    .chain(self.child_index.to_bits().to_be_bytes().iter()),
            ),
        ) {
            *src = *dst;
        }
        bytes
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut bytes = [0u8; Self::LENGTH];
        for (src, dst) in bytes.iter_mut().zip(
            [self.depth].iter().chain(
                self.parent_fingerprint.iter().chain(
                    self.child_index
                        .to_bits()
                        .to_be_bytes()
                        .iter()
                        .chain(self.chain_code.iter()),
                ),
            ),
        ) {
            *src = *dst;
        }
        bytes
    }

    #[inline]
    pub fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LENGTH {
            return errbang!(
                err::InvalidLenSize,
                "{} must be {}",
                bytes.len(),
                Self::LENGTH
            );
        }

        let depth = bytes[0];

        let mut l = 1 + consts::FINGERPRINT_LENGTH;

        let mut parent_fingerprint = [0u8; consts::FINGERPRINT_LENGTH];
        parent_fingerprint.copy_from_slice(&bytes[1..l]);

        let child_index = ChildIndex::from_bits(u32::from_be_bytes(errcast!(
            (&bytes[l..l + consts::CHILDINDEX_LENGTH]).try_into(),
            err::Parser
        )));
        l += consts::CHILDINDEX_LENGTH;

        let mut chain_code = [0u8; consts::CHAINCODE_LENGTH];
        chain_code.copy_from_slice(&bytes[l..l + consts::CHAINCODE_LENGTH]);
        Ok(Self {
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
        })
    }
}
impl Drop for ExtAttributes {
    fn drop(&mut self) {
        self.depth.zeroize();
        self.parent_fingerprint.zeroize();
        self.chain_code.zeroize();
    }
}

pub type PrefixNumbs = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtPrefix {
    pub chars: [u8; Self::LENGTH],
    pub numbs: PrefixNumbs,
}

impl ExtPrefix {
    /// 4 bytes
    pub const LENGTH: usize = consts::PREFIX_LENGTH;
    pub const CHARS_TPRV: &'static str = "tprv";
    pub const CHARS_TPUB: &'static str = "tpub";
    pub const CHARS_XPRV: &'static str = "xprv";
    pub const CHARS_XPUB: &'static str = "xpub";
    pub const NUMBS_TPRV: PrefixNumbs = 0x04358394;
    pub const NUMBS_TPUB: PrefixNumbs = 0x043587cf;
    pub const NUMBS_XPRV: PrefixNumbs = 0x0488ade4;
    pub const NUMBS_XPUB: PrefixNumbs = 0x0488b21e;

    /// testnet secret key
    #[inline]
    pub fn tprv() -> Self {
        Self::new(Self::CHARS_TPRV, Self::NUMBS_TPRV)
    }

    /// testnet public key
    #[inline]
    pub fn tpub() -> Self {
        Self::new(Self::CHARS_TPUB, Self::NUMBS_TPUB)
    }

    /// mainnet secret key
    #[inline]
    pub fn xprv() -> Self {
        Self::new(Self::CHARS_XPRV, Self::NUMBS_XPRV)
    }

    /// mainnet public key
    #[inline]
    pub fn xpub() -> Self {
        Self::new(Self::CHARS_XPUB, Self::NUMBS_XPUB)
    }

    pub fn new(string: &str, numbs: u32) -> Self {
        let mut chars = [0u8; Self::LENGTH];
        chars.copy_from_slice(string.as_bytes());
        Self { chars, numbs }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        errcast_panic!(str::from_utf8(&self.chars), err::Parser)
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.numbs.to_be_bytes()
    }

    #[inline]
    pub fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LENGTH {
            return errbang!(err::InvalidLenSize);
        }
        let mut be_bytes = [0u8; Self::LENGTH];
        be_bytes.copy_from_slice(bytes);
        Ok(match PrefixNumbs::from_be_bytes(be_bytes) {
            Self::NUMBS_TPRV => Self::tprv(),
            Self::NUMBS_TPUB => Self::tpub(),
            Self::NUMBS_XPRV => Self::xprv(),
            Self::NUMBS_XPUB => Self::xpub(),
            _ => return errbang!(err::Parser),
        })
    }
}
impl FromStr for ExtPrefix {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Self::LENGTH {
            return errbang!(err::InvalidLenSize);
        }
        Ok(match s {
            Self::CHARS_TPRV => Self::tprv(),
            Self::CHARS_TPUB => Self::tpub(),
            Self::CHARS_XPRV => Self::xprv(),
            Self::CHARS_XPUB => Self::xpub(),
            _ => return errbang!(err::Parser),
        })
    }
}

impl AsRef<str> for ExtPrefix {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
