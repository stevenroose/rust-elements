// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Partially Signed Transactions
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSBTs containing non-standard SigHash types as invalid.

use blockdata::script::Script;
use blockdata::transaction::Transaction;
use consensus::{encode, Encodable, Decodable};

use std::io;

mod error;
pub use self::error::Error;

pub mod raw;

#[macro_use]
mod macros;

pub mod serialize;

mod map;
pub use self::map::{Map, Global, Input, Output};

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct PartiallySignedTransaction {
    /// The key-value pairs for all global data.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned
    /// transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned
    /// transaction.
    pub outputs: Vec<Output>,
}

impl PartiallySignedTransaction {
    /// Create a PartiallySignedTransaction from an unsigned transaction, error
    /// if not unsigned
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, encode::Error> {
        Ok(PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],
            global: Global::from_unsigned_tx(tx)?,
        })
    }

    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    pub fn extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.global.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_else(|| Script::new());
            vin.witness.script_witness = psbtin.final_script_witness.unwrap_or_else(|| Vec::new());
        }

        tx
    }

    /// Attempt to merge with another `PartiallySignedTransaction`.
    pub fn merge(&mut self, other: Self) -> Result<(), self::Error> {
        self.global.merge(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.merge(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.merge(other_output)?;
        }

        Ok(())
    }
}

impl Encodable for PartiallySignedTransaction {
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += b"psbt".consensus_encode(&mut s)?;

        len += 0xff_u8.consensus_encode(&mut s)?;

        len += self.global.consensus_encode(&mut s)?;

        for i in &self.inputs {
            len += i.consensus_encode(&mut s)?;
        }

        for i in &self.outputs {
            len += i.consensus_encode(&mut s)?;
        }

        Ok(len)
    }
}

impl Decodable for PartiallySignedTransaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let magic: [u8; 4] = Decodable::consensus_decode(&mut d)?;

        if *b"psbt" != magic {
            return Err(Error::InvalidMagic.into());
        }

        if 0xff_u8 != u8::consensus_decode(&mut d)? {
            return Err(Error::InvalidSeparator.into());
        }

        let global: Global = Decodable::consensus_decode(&mut d)?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = (&global.unsigned_tx.input).len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Decodable::consensus_decode(&mut d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = (&global.unsigned_tx.output).len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Decodable::consensus_decode(&mut d)?);
            }

            outputs
        };

        Ok(PartiallySignedTransaction {
            global: global,
            inputs: inputs,
            outputs: outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::hex::FromHex;
    use hashes::sha256d;

    use std::collections::BTreeMap;

    use hex::decode as hex_decode;

    use secp256k1::Secp256k1;

    use blockdata::confidential;
    use blockdata::script::Script;
    use blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use network::constants::Network::Bitcoin;
    use consensus::encode::{deserialize, serialize, serialize_hex};
    use util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
    use util::key::PublicKey;
    use util::psbt::map::{Global, Output};
    use util::psbt::raw;

    use super::PartiallySignedTransaction;

    #[test]
    fn trivial_psbt() {
        let psbt = PartiallySignedTransaction {
            global: Global {
                unsigned_tx: Transaction {
                    version: 2,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                unknown: BTreeMap::new(),
            },
            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(
            serialize_hex(&psbt),
            "70736274ff01000a0200000000000000000000"
        );
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let mut hd_keypaths: BTreeMap<PublicKey, (Fingerprint, DerivationPath)> = Default::default();

        let mut sk: ExtendedPrivKey = ExtendedPrivKey::new_master(Bitcoin, &seed).unwrap();

        let fprint: Fingerprint = sk.fingerprint(&secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_priv(secp, &dpath).unwrap();

        let pk: ExtendedPubKey = ExtendedPubKey::from_private(&secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(hex_script!(
                "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
            )),
            witness_script: Some(hex_script!(
                "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
            )),
            hd_keypaths: hd_keypaths,
            ..Default::default()
        };

        let actual: Output = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Global {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: sha256d::Hash::from_hex(
                            "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126",
                        ).unwrap(),
                        vout: 0,
                    },
                    script_sig: Script::new(),
                    sequence: 4294967294,
					is_pegin: false,
					has_issuance: false,
					asset_issuance: Default::default(),
                    witness: Default::default(),
                }],
                output: vec![
                    TxOut {
                        value: confidential::Value::Explicit(99999699),
                        script_pubkey: hex_script!(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"
                        ),
						asset: confidential::Asset::Explicit(Default::default()),
						nonce: confidential::Nonce::Null,
						witness: Default::default(),
                    },
                    TxOut {
                        value: confidential::Value::Explicit(100000000),
                        script_pubkey: hex_script!(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"
                        ),
						asset: confidential::Asset::Explicit(Default::default()),
						nonce: confidential::Nonce::Null,
						witness: Default::default(),
                    },
                ],
            },
            unknown: Default::default(),
        };

        let actual: Global = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key {
                type_value: 0u8,
                key: vec![42u8, 69u8],
            },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual: raw::Pair = deserialize(&serialize(&expected)).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn deserialize_and_serialize_psbt_with_two_partial_sigs() {
        let hex = "70736274ff0100890200000001207ae985d787dfe6143d5c58fad79cc7105e0e799fcf033b7f2ba17e62d7b3200000000000ffffffff02563d03000000000022002019899534b9a011043c0dd57c3ff9a381c3522c5f27c6a42319085b56ca543a1d6adc020000000000220020618b47a07ebecca4e156edb1b9ea7c24bdee0139fc049237965ffdaf56d5ee73000000000001012b801a0600000000002200201148e93e9315e37dbed2121be5239257af35adc03ffdfc5d914b083afa44dab82202025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee076473044022007e06b362e89912abd4661f47945430739b006a85d1b2a16c01dc1a4bd07acab022061576d7aa834988b7ab94ef21d8eebd996ea59ea20529a19b15f0c9cebe3d8ac01220202b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a473044022002787f926d6817504431ee281183b8119b6845bfaa6befae45e13b6d430c9d2f02202859f149a6cd26ae2f03a107e7f33c7d91730dade305fe077bae677b5d44952a01010547522102b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a21025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee07652ae0001014752210283ef76537f2d58ae3aa3a4bd8ae41c3f230ccadffb1a0bd3ca504d871cff05e7210353d79cc0cb1396f4ce278d005f16d948e02a6aec9ed1109f13747ecb1507b37b52ae00010147522102b3937241777b6665e0d694e52f9c1b188433641df852da6fc42187b5d8a368a321034cdd474f01cc5aa7ff834ad8bcc882a87e854affc775486bc2a9f62e8f49bd7852ae00";
        let psbt: PartiallySignedTransaction = hex_psbt!(hex).unwrap();
        assert_eq!(hex, serialize_hex(&psbt));
    }
}
