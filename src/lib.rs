// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

//! # ***`ed25519-dalek-xkeypair`***
//! *BIP32 implementation for ed25519-dalek key pairs.*

#![cfg_attr(not(feature = "std"), no_std)]

pub extern crate derivation_path;
pub extern crate ed25519_dalek;

mod errors;
mod key;
mod types;

pub use derivation_path::DerivationPath;
pub use key::ExtendedKeypair;
pub use types::{consts, ExtPrefix, PublicKey, SecretKey};

#[cfg(feature = "default")]
extern crate alloc;

#[doc(hidden)]
pub mod private {
    #[cfg(feature = "default")]
    pub use alloc::vec::Vec;
    #[cfg(feature = "default")]
    pub use core::{
        convert::TryInto,
        fmt::{self, Display},
        ops::{Deref, DerefMut},
        str::{self, FromStr},
    };
    #[cfg(feature = "std")]
    pub use std::{
        convert::TryInto,
        fmt::{self, Display},
        ops::{Deref, DerefMut},
        str::{self, FromStr},
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ParentFingerprint;
    use types::{ChildIndex, DalekKeypair, ExtAttributes};

    use core::convert::TryInto;

    fn root(seed: &str) -> ExtendedKeypair {
        ExtendedKeypair::from_seed(&hex::decode(seed).unwrap(), ExtPrefix::tprv()).unwrap()
    }

    fn extract_target(
        depth: u8,
        fingerprint: ParentFingerprint,
        child_index: ChildIndex,
        chain_code: &str,
        secret_bytes: &str,
    ) -> (ExtAttributes, DalekKeypair) {
        (
            ExtAttributes::new(
                depth,
                fingerprint,
                child_index,
                hex::decode(chain_code).unwrap().try_into().unwrap(),
            ),
            ExtendedKeypair::dalekpair_from_secret_bytes(&hex::decode(secret_bytes).unwrap())
                .unwrap(),
        )
    }

    fn assert_node_vs_target(node: &ExtendedKeypair, target: (ExtAttributes, DalekKeypair)) {
        let attrs = node.attrs();
        let pair = node.pair();
        assert_eq!(attrs, &target.0);
        assert_eq!(pair.secret.as_bytes(), target.1.secret.as_bytes());
        assert_eq!(pair.public.as_bytes(), target.1.public.as_bytes());
    }

    #[test]
    fn bytes_conversion() {
        let xpair = root("000102030405060708090a0b0c0d0e0f");
        let xpair_bytes = xpair.to_bytes();
        let xpair2 = ExtendedKeypair::from_bytes(&xpair_bytes).unwrap();
        assert_eq!(xpair, xpair2);
        assert_eq!(
            xpair.pair().secret.as_bytes(),
            xpair2.pair().secret.as_bytes()
        );
        assert_eq!(
            xpair.pair().public.as_bytes(),
            xpair2.pair().public.as_bytes()
        );
    }

    #[test]
    fn prefix() {
        let xpair = root("000102030405060708090a0b0c0d0e0f");
        let tprv: ExtPrefix = "tprv".parse().unwrap();
        assert_eq!(xpair.prefix(), &tprv);
    }

    #[test]
    fn path_derivation() {
        let vector1_path: DerivationPath = "m/0'/1'/2'/2'/1000000000'".parse().unwrap();
        let vector2_path: DerivationPath = "m/0'/2147483647'/1'/2147483646'/2'".parse().unwrap();

        let node = root("000102030405060708090a0b0c0d0e0f")
            .derive(&vector1_path)
            .unwrap();
        let target = extract_target(
            5,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(1000000000),
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        );
        assert_node_vs_target(&node, target);

        let node = root("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").derive(&vector2_path).unwrap();
        let target = extract_target(
            5,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2),
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        );
        assert_node_vs_target(&node, target);
    }

    #[test]
    fn validator() {
        let node = root("000102030405060708090a0b0c0d0e0f");
        assert!(node.derive_child(0).is_ok());
        assert!(node.derive_child(100000).is_ok());
        let soft_path: DerivationPath = "m/0'/1'/2'/3/4'".parse().unwrap();
        assert!(node.derive(&soft_path).is_err());
    }

    #[test]
    fn vector1() {
        // Chain m
        let node = root("000102030405060708090a0b0c0d0e0f");
        let target = extract_target(
            0,
            node.attrs().parent_fingerprint,
            ChildIndex::Normal(0),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'
        let node = node.derive_child(0).unwrap();
        let target = extract_target(
            1,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(0),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/1'
        let node = node.derive_child(1).unwrap();
        let target = extract_target(
            2,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(1),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/1'/2'
        let node = node.derive_child(2).unwrap();
        let target = extract_target(
            3,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2),
            "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/1'/2'/2'
        let node = node.derive_child(2).unwrap();
        let target = extract_target(
            4,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2),
            "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/1'/2'/2'/1000000000'
        let node = node.derive_child(1000000000).unwrap();
        let target = extract_target(
            5,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(1000000000),
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        );
        assert_node_vs_target(&node, target);
    }

    #[test]
    fn vector2() {
        // Chain m
        let node = root("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        let target = extract_target(
            0,
            node.attrs().parent_fingerprint,
            ChildIndex::Normal(0),
            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'
        let node = node.derive_child(0).unwrap();
        let target = extract_target(
            1,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(0),
            "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/2147483647'
        let node = node.derive_child(2147483647).unwrap();

        let target = extract_target(
            2,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2147483647),
            "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/2147483647'/1'
        let node = node.derive_child(1).unwrap();

        let target = extract_target(
            3,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(1),
            "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/2147483647'/1'/2147483646'
        let node = node.derive_child(2147483646).unwrap();
        let target = extract_target(
            4,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2147483646),
            "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
        );
        assert_node_vs_target(&node, target);

        // Chain m/0'/2147483647'/1'/2147483646'/2'
        let node = node.derive_child(2).unwrap();
        let target = extract_target(
            5,
            node.attrs().parent_fingerprint,
            ChildIndex::Hardened(2),
            "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        );
        assert_node_vs_target(&node, target);
    }
}
