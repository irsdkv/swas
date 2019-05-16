//! SWAS
//!
//! This module defines structions and functions for performing swaps
//!

pub extern crate exonum_bitcoinrpc_zec_exp;
extern crate bitcoin;
extern crate bitcoin_zcash;
extern crate zcash;
extern crate rand;
extern crate crypto;
extern crate serde;
extern crate serde_json;
extern crate byteorder;
extern crate rustc_serialize;
extern crate secp256k1;
extern crate failure;

use std::fmt;
use std::str::FromStr;
use std::convert::From;
use std::iter::Iterator;
use self::rustc_serialize::hex::{FromHex, ToHex};
use self::serde::ser::{Serialize, Serializer, SerializeStruct};
use self::serde::de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};
use self::crypto::digest::Digest;
use self::crypto::sha2::{Sha256};
use self::bitcoin::blockdata::opcodes::All::OP_NOP2 as OP_CHECKLOCKTIMEVERIFY;
use self::bitcoin::blockdata::opcodes::All::OP_PUSHNUM_1 as OP_TRUE;
use self::bitcoin::blockdata::transaction::Transaction as BtcTransaction;
use self::bitcoin::network::serialize::{SimpleEncoder, SimpleDecoder, BitcoinHash};
use self::bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable};
use self::bitcoin::util::address::Address as BtcAddress;
use self::bitcoin_zcash::blockdata::transaction::Transaction as ZecTransaction;
use self::bitcoin_zcash::blockdata::opcodes::All::OP_PUSHNUM_1 as OP_TRUE_ZEC;
use self::bitcoin_zcash::blockdata::opcodes::All::OP_PUSHBYTES_0 as OP_FALSE_ZEC;
use self::bitcoin_zcash::util::address::Address as ZecAddress;
use self::bitcoin_zcash::blockdata::transaction::TxHeader;

/// Satoshi/Zatoshi amount in 1 BTC/ZEC
pub const SATOSHI_AMOUNT : f64 = 100_000_000.0;
const TRADE_VERSION : u16 = 1;

#[derive(Clone, Debug)]
struct WalletsBtc {
    initiator : BtcAddress,
    fulfiller : BtcAddress,
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for WalletsBtc {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        format!("{}", self.initiator).consensus_encode(s)?;
        format!("{}", self.fulfiller).consensus_encode(s)
    }
}

fn expect_string(s: String) -> String {
    s
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for WalletsBtc {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<WalletsBtc,  bitcoin::network::serialize::Error> {
        Ok(WalletsBtc {
            initiator: BtcAddress::from_str(&expect_string(ConsensusDecodable::consensus_decode(d)?))?,
            fulfiller: BtcAddress::from_str(&expect_string(ConsensusDecodable::consensus_decode(d)?))?,
        })
    }
}

impl WalletsBtc {
    pub fn new(initiator : BtcAddress, fulfiller : BtcAddress) -> WalletsBtc {
        WalletsBtc {
            initiator: initiator,
            fulfiller: fulfiller,
        }
    }
    fn from_strs(initiator : String, fulfiller : String) -> WalletsBtc {
        WalletsBtc {
            initiator: BtcAddress::from_str(&initiator).unwrap(),
            fulfiller: BtcAddress::from_str(&fulfiller).unwrap(),
        }
    }
}

impl Serialize for WalletsBtc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WalletsBtc", 2)?;
        state.serialize_field("initiator", &self.initiator.to_string())?;
        state.serialize_field("fulfiller", &self.fulfiller.to_string())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WalletsBtc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Initiator, Fulfiller };

        struct WalletsBtcVisitor;

        impl<'de> Visitor<'de> for WalletsBtcVisitor {
            type Value = WalletsBtc;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct WalletsBtc")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<WalletsBtc, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let initiator = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let fulfiller = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(WalletsBtc::from_strs(initiator, fulfiller))
            }

            fn visit_map<V>(self, mut map: V) -> Result<WalletsBtc, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut initiator = None;
                let mut fulfiller = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Initiator => {
                            if initiator.is_some() {
                                return Err(de::Error::duplicate_field("initiator"));
                            }
                            initiator = Some(map.next_value()?);
                        }
                        Field::Fulfiller => {
                            if fulfiller.is_some() {
                                return Err(de::Error::duplicate_field("fulfiller"));
                            }
                            fulfiller = Some(map.next_value()?);
                        }
                    }
                }
                let initiator = initiator.ok_or_else(|| de::Error::missing_field("initiator"))?;
                let fulfiller = fulfiller.ok_or_else(|| de::Error::missing_field("fulfiller"))?;
                Ok(WalletsBtc::from_strs(initiator, fulfiller))
            }
        }

        const FIELDS: &'static [&'static str] = &["initiator", "fulfiller"];
        deserializer.deserialize_struct("WalletsBtc", FIELDS, WalletsBtcVisitor)
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
struct ExchangeDataBtc {
    wallets : WalletsBtc,
    script : bitcoin::blockdata::script::Script,
    amount : f64,
    locktime : u64,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ExchangeDataBtc {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ExchangeDataBtc,  bitcoin::network::serialize::Error> {
        Ok (ExchangeDataBtc {
            wallets: ConsensusDecodable::consensus_decode(d)?,
            script: ConsensusDecodable::consensus_decode(d)?,
            amount:  {
                let a: u64 = ConsensusDecodable::consensus_decode(d)?;
                a as f64 / SATOSHI_AMOUNT
            },
            locktime: ConsensusDecodable::consensus_decode(d)?,
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ExchangeDataBtc {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        self.wallets.consensus_encode(s)?;
        self.script.to_bytes().consensus_encode(s)?;
        ((self.amount * SATOSHI_AMOUNT) as u64).consensus_encode(s)?;
        self.locktime.consensus_encode(s)
    }
}

impl ExchangeDataBtc {
    #[allow(dead_code)]
    fn new(wallets : WalletsBtc,
            script : bitcoin::blockdata::script::Script,
            amount : f64,
            locktime : u64) -> ExchangeDataBtc {
        ExchangeDataBtc {
            wallets: wallets,
            script: script,
            amount: amount,
            locktime: locktime,
        }
    }
}

#[derive(Clone, Debug)]
struct WalletsZec {
    initiator : ZecAddress,
    fulfiller : ZecAddress,
}

fn ze_to_be(e: bitcoin_zcash::network::serialize::Error) -> bitcoin::network::serialize::Error {
    use swas::bitcoin::network::serialize::Error::{*};
    match e {
        bitcoin_zcash::network::serialize::Error::Io(e) => return Io(e),
        bitcoin_zcash::network::serialize::Error::Base58(_) => return UnexpectedNetworkMagic{
                                                                                            expected: 0,
                                                                                            actual: 0
                                                                                        },
        bitcoin_zcash::network::serialize::Error::Bech32(e) => return Bech32(e),
        bitcoin_zcash::network::serialize::Error::ByteOrder(_) => return UnexpectedNetworkMagic{
                                                                                            expected: 0,
                                                                                            actual: 0
                                                                                        },
        bitcoin_zcash::network::serialize::Error::UnexpectedNetworkMagic{expected: e, actual: a} => return UnexpectedNetworkMagic{
                                                                                            expected: e,
                                                                                            actual: a
                                                                                        },
        bitcoin_zcash::network::serialize::Error::OversizedVectorAllocation{requested: r, max: m} => return OversizedVectorAllocation{
                                                                                            requested: r,
                                                                                            max: m
                                                                                        },
        bitcoin_zcash::network::serialize::Error::InvalidChecksum{expected: r, actual: m} => return InvalidChecksum{
                                                                                            expected: r,
                                                                                            actual: m
                                                                                        },
        bitcoin_zcash::network::serialize::Error::UnknownNetworkMagic(m) => return UnknownNetworkMagic(m),
        bitcoin_zcash::network::serialize::Error::ParseFailed(m) => return ParseFailed(m),
        bitcoin_zcash::network::serialize::Error::UnsupportedWitnessVersion(m) => return UnsupportedWitnessVersion(m),
        bitcoin_zcash::network::serialize::Error::UnsupportedSegwitFlag(m) => return UnsupportedSegwitFlag(m),
        bitcoin_zcash::network::serialize::Error::UnrecognizedNetworkCommand(m) => return UnrecognizedNetworkCommand(m),
        bitcoin_zcash::network::serialize::Error::UnexpectedHexDigit(m) => return UnexpectedHexDigit(m),
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for WalletsZec {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<WalletsZec,  bitcoin::network::serialize::Error> {
        Ok(WalletsZec {
            initiator: match ZecAddress::from_str(&expect_string(ConsensusDecodable::consensus_decode(d)?)) {
                Err(e) => return Err(ze_to_be(e)),
                Ok(addr) => addr
            },
            fulfiller: match ZecAddress::from_str(&expect_string(ConsensusDecodable::consensus_decode(d)?)) {
                Err(e) => return Err(ze_to_be(e)),
                Ok(addr) => addr
            },
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for WalletsZec {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        format!("{}", self.initiator).consensus_encode(s)?;
        format!("{}", self.fulfiller).consensus_encode(s)
    }
}

impl WalletsZec {
    pub fn new(initiator : ZecAddress, fulfiller : ZecAddress) -> WalletsZec {
        WalletsZec {
            initiator: initiator,
            fulfiller: fulfiller,
        }
    }
    fn from_strs(initiator : String, fulfiller : String) -> WalletsZec {
        WalletsZec {
            initiator: ZecAddress::from_str(&initiator).unwrap(),
            fulfiller: ZecAddress::from_str(&fulfiller).unwrap(),
        }
    }
}

impl Serialize for WalletsZec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WalletsZec", 2)?;
        state.serialize_field("initiator", &self.initiator.to_string())?;
        state.serialize_field("fulfiller", &self.fulfiller.to_string())?;
        state.end()
    }
}
impl<'de> Deserialize<'de> for WalletsZec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Initiator, Fulfiller };

        struct WalletsZecVisitor;

        impl<'de> Visitor<'de> for WalletsZecVisitor {
            type Value = WalletsZec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct WalletsZec")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<WalletsZec, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let initiator = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let fulfiller = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(WalletsZec::from_strs(initiator, fulfiller))
            }

            fn visit_map<V>(self, mut map: V) -> Result<WalletsZec, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut initiator = None;
                let mut fulfiller = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Initiator => {
                            if initiator.is_some() {
                                return Err(de::Error::duplicate_field("initiator"));
                            }
                            initiator = Some(map.next_value()?);
                        }
                        Field::Fulfiller => {
                            if fulfiller.is_some() {
                                return Err(de::Error::duplicate_field("fulfiller"));
                            }
                            fulfiller = Some(map.next_value()?);
                        }
                    }
                }
                let initiator = initiator.ok_or_else(|| de::Error::missing_field("initiator"))?;
                let fulfiller = fulfiller.ok_or_else(|| de::Error::missing_field("fulfiller"))?;
                Ok(WalletsZec::from_strs(initiator, fulfiller))
            }
        }

        const FIELDS: &'static [&'static str] = &["initiator", "fulfiller"];
        deserializer.deserialize_struct("WalletsZec", FIELDS, WalletsZecVisitor)
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
enum WalletsData {
    WBtc(WalletsBtc),
    WZec(WalletsZec)
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for WalletsData {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<WalletsData,  bitcoin::network::serialize::Error> {
        match expect_string(ConsensusDecodable::consensus_decode(d)?).as_ref() {
            "b" => Ok(WalletsData::WBtc(ConsensusDecodable::consensus_decode(d)?)),
            "z" => Ok(WalletsData::WZec(ConsensusDecodable::consensus_decode(d)?)),
            _ => Err(bitcoin::network::serialize::Error::ParseFailed("expected 'b' or 'z'"))

        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for WalletsData {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        match self {
            WalletsData::WBtc(wallet) => {
                "b".to_string().consensus_encode(s)?;
                wallet.consensus_encode(s)
            },
            WalletsData::WZec(wallet) => {
                "z".to_string().consensus_encode(s)?;
                wallet.consensus_encode(s)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
struct ExchangeDataZec {
    wallets : WalletsZec,
    script : bitcoin_zcash::blockdata::script::Script,
    amount : f64,
    locktime : u64,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ExchangeDataZec {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ExchangeDataZec,  bitcoin::network::serialize::Error> {
        Ok (ExchangeDataZec {
            wallets: ConsensusDecodable::consensus_decode(d)?,
            script: {
                let s:  bitcoin::blockdata::script::Script = ConsensusDecodable::consensus_decode(d)?;
                bitcoin_zcash::blockdata::script::Script::from(s.as_bytes().to_vec())},
            amount: {
                let a: u64 = ConsensusDecodable::consensus_decode(d)?;
                a as f64 / SATOSHI_AMOUNT
            },
            locktime: ConsensusDecodable::consensus_decode(d)?,
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ExchangeDataZec {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        self.wallets.consensus_encode(s)?;
        self.script.to_bytes().consensus_encode(s)?;
        ((self.amount * SATOSHI_AMOUNT) as u64).consensus_encode(s)?;
        self.locktime.consensus_encode(s)
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
enum ExchangeData {
    Btc(ExchangeDataBtc),
    Zec(ExchangeDataZec)
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ExchangeData {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ExchangeData,  bitcoin::network::serialize::Error> {
        match expect_string(ConsensusDecodable::consensus_decode(d)?).as_ref() {
            "t" => Ok(ExchangeData::Btc(ConsensusDecodable::consensus_decode(d)?)),
            "e" => Ok(ExchangeData::Zec(ConsensusDecodable::consensus_decode(d)?)),
            _ => Err(bitcoin::network::serialize::Error::ParseFailed("expected 'db' or 'dz'"))
        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ExchangeData {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        match self {
            ExchangeData::Btc(exdata) => {
                "t".to_string().consensus_encode(s)?;
                exdata.consensus_encode(s)
            },
            ExchangeData::Zec(exdata) => {
                "e".to_string().consensus_encode(s)?;
                exdata.consensus_encode(s)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
struct ContractParams {
    exchange_data_coin_buy : ExchangeData,
    exchange_data_coin_sell : ExchangeData,
    secret: Option<Vec<u8>>,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ContractParams {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ContractParams,  bitcoin::network::serialize::Error> {
        Ok (ContractParams {
            exchange_data_coin_buy: ConsensusDecodable::consensus_decode(d)?,
            exchange_data_coin_sell: ConsensusDecodable::consensus_decode(d)?,
            secret: ConsensusDecodable::consensus_decode(d)?,
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ContractParams {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        self.exchange_data_coin_buy.consensus_encode(s)?;
        self.exchange_data_coin_sell.consensus_encode(s)?;
        self.secret.consensus_encode(s)
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
enum ContractStageInitiator {
    Undef(ContractParams),
    Init(ContractParams),
    Funded(ContractParams),
    FulfillerFunded(ContractParams),
    Complete(ContractParams),
    Refunded(ContractParams)
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ContractStageInitiator {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ContractStageInitiator,  bitcoin::network::serialize::Error> {
        Ok(ContractStageInitiator::Undef(ConsensusDecodable::consensus_decode(d)?))
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ContractStageInitiator {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        use self::ContractStageInitiator::{*};
        match self {
            Undef(params) => params.consensus_encode(s),
            Init(params) => params.consensus_encode(s),
            Funded(params) => params.consensus_encode(s),
            FulfillerFunded(params) => params.consensus_encode(s),
            Complete(params) => params.consensus_encode(s),
            Refunded(params) => params.consensus_encode(s),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
enum ContractStageFulfiller {
    Undef(ContractParams),
    Init(ContractParams),
    InitiatorFunded(ContractParams),
    Funded(ContractParams),
    InitiatorRedeemed(ContractParams),
    Complete(ContractParams),
    Refunded(ContractParams)
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ContractStageFulfiller {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ContractStageFulfiller,  bitcoin::network::serialize::Error> {
        Ok(ContractStageFulfiller::Undef(ConsensusDecodable::consensus_decode(d)?))
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ContractStageFulfiller {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        use self::ContractStageFulfiller::{*};
        match self {
            Undef(params) => params.consensus_encode(s),
            Init(params) => params.consensus_encode(s),
            InitiatorFunded(params) => params.consensus_encode(s),
            Funded(params) => params.consensus_encode(s),
            InitiatorRedeemed(params) => params.consensus_encode(s),
            Complete(params) => params.consensus_encode(s),
            Refunded(params) => params.consensus_encode(s),
        }
    }
}

/// A library error
#[derive(Fail, Debug, Display)]
pub enum TradeError {
    #[fail(display = "Invalid stage: {:?}", _0)]
    InvalidStage(Stage),
    #[fail(display = "Already redeemed stage")]
    AlreadyRedeemed,
    #[fail(display = "Invalid role: {:?})", _0)]
    InvalidRole(Role),
    #[fail(display = "Rpc call failed: {} : {}", call, rpc_err)]
    RpcError{
        call: String,
        rpc_err: exonum_bitcoinrpc_zec_exp::Error
    },
    #[fail(display = "Invalid Amount: {}", _0)]
    InvalidAmount(f64),
    #[fail(display = "Unsupported address: {} ({})", addr, comment)]
    UnsupportedAddress{
        addr: Address,
        comment: String
    },
    #[fail(display = "Invalid bitcoin address: {}", _0)]
    InvalidBtcAddress(String),
    #[fail(display = "Invalid zcash address: {}", _0)]
    InvalidZecAddress(String),
    #[fail(display = "Bitcoin address type {:?} not supported", _0)]
    NotSupportedBtcAddress(bitcoin::util::address::Payload),
    #[fail(display = "Zcash address type {:?} not supported", _0)]
    NotSupportedZecAddress(bitcoin_zcash::util::address::Payload),
    #[fail(display = "Invalid bitcoin script_sig: {:?}", _0)]
    InvalidBtcScriptSig(bitcoin::blockdata::script::Script),
    #[fail(display = "Invalid zcash script_sig: {:?}", _0)]
    InvalidZecScriptSig(bitcoin_zcash::blockdata::script::Script),
    #[fail(display = "Too small balance on {} address (balance: {}, expected: {})",
                        addr, current, expected)]
    TooSmallBalance{
        addr: Address,
        current: f64,
        expected: f64
    },
    #[fail(display = "Refunt attempt too early: current blocknum {}, expected at least {}", current_blocknum, expected_blocknum)]
    RefundAttemptTooEarly {
        current_blocknum: u64,
        expected_blocknum: u64
    },
    #[fail(display = "Nothing to spend (no available txins) from {} address.", _0)]
    NothingToSpend(Address),
    #[fail(display = "Private key for {} address is not known.", _0)]
    PrivKeyNotFound(Address),
    #[fail(display = "Invalid import string: {}.", _0)]
    InvalidImportString(String),
    #[fail(display = "Concensus Encode Error")]
    ConcensusEncodeError,
    #[fail(display = "Default")]
    Default,
    #[fail(display = "Bitcoin consensus error: {}", _0)]
    NetworkConsensusError(bitcoin::network::serialize::Error),
    #[fail(display = "Other: {}", _0)]
    Other(String)
}

impl Default for TradeError {
    fn default() -> Self { TradeError::Default }
}

/// Trade result type
pub type TradeResult<T> = ::std::result::Result<T, TradeError>;

/// Blockchain address
#[derive(Fail, Debug, Display)]
pub enum Address {
    #[fail(display = "bitcoin {:?}", _0)]
    Btc(BtcAddress),
    #[fail(display = "zcash {:?}", _0)]
    Zec(ZecAddress)
}

/// Trade stage
#[derive(Clone, PartialEq, Debug, Display)]
pub enum Stage {
    /// Role: Initiator
    ///
    /// Stage: Undefined
    InitiatorUndef,
    /// Role: Initiator
    ///
    ///  Stage: Inited
    InitiatorInit,
    /// Role: Initiator
    ///
    ///  Stage: Initiator was Funded, fulfiller funded not yet
    InitiatorFunded,
    /// Role: Initiator
    ///
    ///  Stage: Initiator was funded, fulfiller funded (all funds collected)
    InitiatorFulfillerFunded,
    /// Role: Initiator
    ///
    ///  Stage: Complete (all needed funds redeemed)
    InitiatorComplete,
    /// Role: Initiator
    ///
    ///  Stage: Complete (own funds refunded)
    InitiatorRefunded,
    /// Role: Fulfiller
    ///
    ///  Stage: Undefined
    FulfillerUndef,
    /// Role: Fulfiller
    ///
    ///  Stage: Inited
    FulfillerInit,
    /// Role: Fulfiller
    ///
    ///  Stage: Initator was funded, fulfiller not yet
    FulfillerInitiatorFunded,
    /// Role: Fulfiller
    ///
    ///  Stage: Initator was funded, fulfiller funded (all funds collected)
    FulfillerFunded,
    /// Role: Fulfiller; Stage: Initiator was redeemed
    FulfillerInitiatorRedeemed,
    /// Role: Fulfiller
    ///
    ///  Stage:  Complete (all needed funds redeemed)
    FulfillerComplete,
    /// Role: Fulfiller
    ///
    ///  Stage: Complete (own funds refunded)
    FulfillerRefunded,
}

/// Currencies
#[derive(Clone, PartialEq, Debug, Display)]
pub enum Currency {
    /// Bitcoin
    Bitcoin,
    /// Zcash
    Zcash
}

/// Role in trade
#[derive(Serialize, Deserialize)]
#[derive(Clone, PartialEq, Debug, Display)]
pub enum Role {
    /// Initiator
    Initiator,
    /// Fulfiller
    Fulfiller
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
enum Contract {
    Initiator(ContractStageInitiator),
    Fulfiller(ContractStageFulfiller)
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Contract {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Contract,  bitcoin::network::serialize::Error> {
        match expect_string(ConsensusDecodable::consensus_decode(d)?).as_ref() {
            "i" => Ok(Contract::Initiator(ConsensusDecodable::consensus_decode(d)?)),
            "f" => Ok(Contract::Fulfiller(ConsensusDecodable::consensus_decode(d)?)),
            _ => Err(bitcoin::network::serialize::Error::ParseFailed("expected 'i' or 'f'"))
        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Contract {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        match self {
            Contract::Initiator(contract) => {
                "i".to_string().consensus_encode(s)?;
                contract.consensus_encode(s)
            }
            Contract::Fulfiller(contract) => {
                "f".to_string().consensus_encode(s)?;
                contract.consensus_encode(s)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone, Debug)]
/// Trade object
pub struct Trade {
    version: u16,
    id : String,
    contract : Contract,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Trade {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Trade,  bitcoin::network::serialize::Error> {
        Ok(Trade {
            version: ConsensusDecodable::consensus_decode(d)?,
            id: ConsensusDecodable::consensus_decode(d)?,
            contract: ConsensusDecodable::consensus_decode(d)?
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Trade {
    fn consensus_encode(&self, s: &mut S) -> Result <(), bitcoin::network::serialize::Error> {
        self.version.consensus_encode(s)?;
        self.id.consensus_encode(s)?;
        self.contract.consensus_encode(s)
    }
}

impl BitcoinHash for Trade {
    fn bitcoin_hash(&self) -> bitcoin::util::hash::Sha256dHash {
        use self::bitcoin::util::hash::Sha256dEncoder;
        let mut enc = Sha256dEncoder::new();
        self.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}

/// Data for currency to exchange
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct TradeBlankCurParams {
    /// Amount to exchange in BTC/ZEC
    pub amount: Option<f64>,
    /// Locktime in blocks
    pub locktime: Option<u64>,
    /// Maximum fee for P2WSH to redeem
    pub max_fee: Option<u32>,
    /// Minimal confirmation height
    pub confirmation_height: Option<u64>,
}

/// Trade parameters
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct TradeBlankParams {
    /// Data to sell
    pub sell: Option<TradeBlankCurParams>,
    /// Data to buy
    pub buy: Option<TradeBlankCurParams>,
}

/// Exchange parameters
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub enum TradeBlankParameters {
    /// BTC buy, ZEC sell
    BtcToZec(TradeBlankParams),
    /// ZEC buy, BTC sell
    ZecToBtc(TradeBlankParams)
}

/// Participant's wallet parameters
#[derive(Clone)]
pub struct TradeBlankParticipant {
    /// Bitcoin address
    pub addr_btc: Option<BtcAddress>,
    /// Zcash address
    pub addr_zec: Option<ZecAddress>,
    /// Private key fo Bitcoin address
    pub privkey_btc: Option<secp256k1::key::SecretKey>,
    /// Private key fo Zcash address
    pub privkey_zec: Option<secp256k1::key::SecretKey>,
}

impl<'de> Deserialize<'de> for TradeBlankParticipant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { AddrBtc, AddrZec, PrivkeyBtc, PrivkeyZec};

        struct TradeBlankParticipantVisitor;

        impl<'de> Visitor<'de> for TradeBlankParticipantVisitor {
            type Value = TradeBlankParticipant;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TradeBlankParticipant")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<TradeBlankParticipant, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let secp = secp256k1::Secp256k1::new();
                let addr_btc = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let addr_btc = if addr_btc == "null" {None}
                                else {Some(BtcAddress::from_str(addr_btc).unwrap())};
                let addr_zec = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let addr_zec = if addr_zec == "null" {None}
                                else {Some(ZecAddress::from_str(addr_zec).unwrap())};
                let privkey_btc: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let privkey_btc = if privkey_btc == "null" {None}
                                    else {Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_btc.from_hex().unwrap().as_slice()).unwrap())};
                let privkey_zec: String = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let privkey_zec = if privkey_zec == "null" {None}
                                    else {Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_zec.from_hex().unwrap().as_slice()).unwrap())};
                Ok(TradeBlankParticipant {addr_btc, addr_zec, privkey_btc, privkey_zec})
            }

            fn visit_map<V>(self, mut map: V) -> Result<TradeBlankParticipant, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut addr_btc = None;
                let mut addr_zec = None;
                let mut privkey_btc:Option<secp256k1::key::SecretKey> = None;
                let mut privkey_zec = None;
                let secp = secp256k1::Secp256k1::new();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AddrBtc => {
                            if addr_btc.is_some() {
                                return Err(de::Error::duplicate_field("addrbtc"));
                            }
                            let val  = map.next_value().unwrap();
                            addr_btc = if val == "null" {None}
                                else {Some(BtcAddress::from_str(val).unwrap())};
                        }
                        Field::AddrZec => {
                            if addr_zec.is_some() {
                                return Err(de::Error::duplicate_field("addrzec"));
                            }
                            let val = map.next_value().unwrap();
                            addr_zec = if val == "null" {None}
                                else {Some(ZecAddress::from_str(val).unwrap())};
                        }
                        Field::PrivkeyBtc => {
                            if privkey_btc.is_some() {
                                return Err(de::Error::duplicate_field("privkeybtc"));
                            }
                            let val:String  = map.next_value().unwrap();
                            privkey_btc = if val == "null" {None}
                                            else {Some(secp256k1::key::SecretKey::from_slice(&secp, val.from_hex().unwrap().as_slice()).unwrap())};
                        }
                        Field::PrivkeyZec => {
                            if privkey_zec.is_some() {
                                return Err(de::Error::duplicate_field("privkeyzec"));
                            }
                            let val:String  = map.next_value().unwrap();
                            privkey_zec = if val == "null" {None}
                                            else {Some(secp256k1::key::SecretKey::from_slice(&secp, val.from_hex().unwrap().as_slice()).unwrap())};
                        }
                    }
                }
                Ok(TradeBlankParticipant {addr_btc, addr_zec, privkey_btc, privkey_zec})
            }
        }
        const FIELDS: &'static [&'static str] = &["addrbtc", "addrzec", "privkeybtc", "privkeyzec"];
        deserializer.deserialize_struct("TradeBlankParticipant", FIELDS, TradeBlankParticipantVisitor)
    }
}

impl Serialize for TradeBlankParticipant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TradeBlankParticipant", 4)?;
        match self.addr_btc {
            Some(ref addr) => state.serialize_field("addrbtc", &format!("{}", addr))?,
            None => state.serialize_field("addrbtc", "null")?,
        };
        match self.addr_zec {
            Some(ref addr) => state.serialize_field("addrzec", &format!("{}", addr))?,
            None => state.serialize_field("addrzec", "null")?,
        };
        match self.privkey_btc {
            Some(key) => state.serialize_field("privkeybtc", &format!("{}", key))?,
            None => state.serialize_field("privkeybtc", "null")?,
        };
        match self.privkey_zec {
            Some(key) => state.serialize_field("privkeyzec", &format!("{}", key))?,
            None => state.serialize_field("privkeyzec", "null")?,
        };
        state.end()
    }
}

/// Blank for create trade object
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct TradeBlank {
    /// Trade ID (name)
    pub id: String,
    /// Own role in contract
    pub role: Role,
    /// Contract's secret vector
    pub secret: Option<Vec<u8>>,
    /// Secret's hash
    pub secret_hash: Option<[u8; 32]>,
    /// Contract's exchange parameters
    pub params: Option<TradeBlankParameters>,
    /// Contract's wallet parameters for initiator
    pub initiator: TradeBlankParticipant,
    /// Contract's wallet parameters for fulfiller
    pub fulfiller: TradeBlankParticipant,
}

impl TradeBlank {
    /// Custom trade blank
    pub fn new(id: String,
            role: Role,
            direction: Option<TradeBlankParameters>,
            initiator: Option<TradeBlankParticipant>,
            fulfiller: Option<TradeBlankParticipant>) -> TradeBlank {
        TradeBlank {
            id: id,
            role: role,
            params: direction,
            secret: None,
            secret_hash: None,
            initiator: {
                match initiator {
                    Some(initiator) => initiator,
                    None => TradeBlankParticipant {
                        addr_btc: None,
                        addr_zec: None,
                        privkey_btc: None,
                        privkey_zec: None,
                    }
                }
            },
            fulfiller: {
                match fulfiller {
                    Some(fulfiller) => fulfiller,
                    None => TradeBlankParticipant {
                        addr_btc: None,
                        addr_zec: None,
                        privkey_btc: None,
                        privkey_zec: None,
                    }
                }
            },
        }
    }

    /// Convert into trade object
    pub fn into_trade(self) -> TradeResult<Trade> {
        match self.role {
            Role::Initiator => {
                match self.params.unwrap() {
                    TradeBlankParameters::BtcToZec(params) => {
                        let wallets_buy = WalletsZec::new(
                            self.initiator.addr_zec.unwrap(),
                            self.fulfiller.addr_zec.unwrap(),
                        );
                        let wallets_sell = WalletsBtc::new(
                            self.initiator.addr_btc.unwrap(),
                            self.fulfiller.addr_btc.unwrap()
                        );
                        Trade::new(
                            self.id,
                            WalletsData::WZec(wallets_buy),
                            params.buy.clone().unwrap().amount.unwrap(),
                            params.buy.unwrap().locktime.unwrap(),
                            WalletsData::WBtc(wallets_sell),
                            params.sell.clone().unwrap().amount.unwrap(),
                            params.sell.unwrap().locktime.unwrap(),
                            self.secret
                        )
                    }
                    TradeBlankParameters::ZecToBtc(params) => {
                        let wallets_buy = WalletsBtc::new(
                            self.initiator.addr_btc.unwrap(),
                            self.fulfiller.addr_btc.unwrap()
                        );
                        let wallets_sell = WalletsZec::new(
                            self.initiator.addr_zec.unwrap(),
                            self.fulfiller.addr_zec.unwrap(),
                        );
                        Trade::new(
                            self.id,
                            WalletsData::WBtc(wallets_buy),
                            params.buy.clone().unwrap().amount.unwrap(),
                            params.buy.unwrap().locktime.unwrap(),
                            WalletsData::WZec(wallets_sell),
                            params.sell.clone().unwrap().amount.unwrap(),
                            params.sell.unwrap().locktime.unwrap(),
                            self.secret
                        )
                    }
                }
            },
            Role::Fulfiller => {
                match self.params.unwrap() {
                    TradeBlankParameters::BtcToZec(params) => {
                        let wallets_buy = WalletsZec::new(
                            self.initiator.addr_zec.unwrap(),
                            self.fulfiller.addr_zec.unwrap(),
                        );
                        let wallets_sell = WalletsBtc::new(
                            self.initiator.addr_btc.unwrap(),
                            self.fulfiller.addr_btc.unwrap()
                        );
                        Trade::new_as_fulfiller(
                            self.id,
                            WalletsData::WZec(wallets_buy),
                            params.buy.clone().unwrap().amount.unwrap(),
                            params.buy.unwrap().locktime.unwrap(),
                            WalletsData::WBtc(wallets_sell),
                            params.sell.clone().unwrap().amount.unwrap(),
                            params.sell.unwrap().locktime.unwrap(),
                            self.secret,
                            self.secret_hash.unwrap()
                        )
                    }
                    TradeBlankParameters::ZecToBtc(params) => {
                        let wallets_buy = WalletsBtc::new(
                            self.initiator.addr_btc.unwrap(),
                            self.fulfiller.addr_btc.unwrap()
                        );
                        let wallets_sell = WalletsZec::new(
                            self.initiator.addr_zec.unwrap(),
                            self.fulfiller.addr_zec.unwrap(),
                        );
                        Trade::new_as_fulfiller(
                            self.id,
                            WalletsData::WBtc(wallets_buy),
                            params.buy.clone().unwrap().amount.unwrap(),
                            params.buy.unwrap().locktime.unwrap(),
                            WalletsData::WZec(wallets_sell),
                            params.sell.clone().unwrap().amount.unwrap(),
                            params.sell.unwrap().locktime.unwrap(),
                            self.secret,
                            self.secret_hash.unwrap()
                        )
                    }
                }
            }
        }
    }
}

/// Wrap to RPC objects
pub enum RpcClient {
    Btc(exonum_bitcoinrpc_zec_exp::Client),
    Zec(exonum_bitcoinrpc_zec_exp::Client)
}

/// Transaction ids
#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub enum Txid {
    /// Bitcoin transaction id
    Btc(bitcoin::util::hash::Sha256dHash),
    /// Zcash transaction id
    Zec(bitcoin_zcash::util::hash::Sha256dHash)
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Txid::Btc(h) => write!(f, r#""Bitcoin": '{}'"#, h),
            Txid::Zec(h) => write!(f, r#""Zcash": '{}'"#, h)
        }
    }
}

#[derive(Clone)]
struct UnspentBtc {
    txins: Vec<bitcoin::blockdata::transaction::TxIn>,
    #[allow(dead_code)]
    amounts_sat: Vec<u64>,
    amount_total: f64
}

#[derive(Clone)]
struct UnspentZec {
    txins: Vec<bitcoin_zcash::blockdata::transaction::TxIn>,
    amounts_sat: Vec<u64>,
    amount_total: f64
}

impl FromStr for Trade {
    type Err = TradeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match serde_json::from_str::<Trade>(s) {
            Ok(realtrade) => Ok(realtrade),
            Err(e) => Err(TradeError::Other(e.to_string()))
        }
    }
}

impl fmt::Display for Trade {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self.get_params().secret {
            None => serde_json::to_string_pretty(&self).unwrap(),
            Some(secret) => {
                let mut secret_string = String::new();
                let secret_len = secret.len();
                for k in 0..(secret_len - 1) {
                    secret_string.push_str(&format!(" {},", secret[k]));
                }
                secret_string.push_str(&format!(" {} ", secret[secret_len - 1]));
                let mut s = serde_json::to_string_pretty(&self).unwrap();
                let mut new_s = String::new();
                let splitted = s.split('[').collect::<Vec<_>>();
                new_s.push_str(splitted[0]);
                new_s.push_str("[");
                new_s.push_str(&secret_string);
                new_s.push_str("]");
                new_s.push_str(splitted[1].split(']').collect::<Vec<_>>()[1]);
                new_s
            }
        };
        write!(f, "{}", s)
    }
}

impl Trade {
    fn new(name : String,
                wallets_buy : WalletsData,
                amount_buy : f64,
                locktime_buy : u64,
                wallets_sell : WalletsData,
                amount_sell : f64,
                locktime_sell : u64,
                secret: Option<Vec<u8>>
            ) -> TradeResult<Trade>
    {
        use self::rand::{thread_rng, Rng};
        match secret {
            Some(secret) => {
                Self::new_with_secret(
                    name,
                    wallets_buy,
                    amount_buy,
                    locktime_buy,
                    wallets_sell,
                    amount_sell,
                    locktime_sell,
                    secret
                )
            },
            None => {
                let mut secret = [0u8; 32];
                thread_rng().fill(&mut secret[..]);
                Self::new_with_secret(
                    name,
                    wallets_buy,
                    amount_buy,
                    locktime_buy,
                    wallets_sell,
                    amount_sell,
                    locktime_sell,
                    secret.to_vec()
                )
            }
        }
    }

    fn new_with_secret(name: String,
                wallets_buy: WalletsData,
                amount_buy: f64,
                locktime_buy: u64,
                wallets_sell: WalletsData,
                amount_sell: f64,
                locktime_sell: u64,
                secret: Vec<u8>
            ) -> TradeResult<Trade> {
    let mut hasher = Sha256::new();
    hasher.input(&secret);
    let mut hasresvec: [u8; 32] = [0; 32];
    hasher.result(&mut hasresvec);
    let (name, exch_data_in, exch_data_out) = Self::get_fields(name, wallets_buy, amount_buy, locktime_buy,
                                                                     wallets_sell, amount_sell, locktime_sell, hasresvec)?;
        Ok(Trade {
            version: TRADE_VERSION,
            id: name,
            contract: Contract::Initiator(
                ContractStageInitiator::Undef(
                    ContractParams {
                        exchange_data_coin_buy: exch_data_in,
                        exchange_data_coin_sell: exch_data_out,
                        secret: Some(secret)
                    }
                )
            )
        })
    }

    fn new_as_fulfiller(name: String,
                wallets_buy: WalletsData,
                amount_buy: f64,
                locktime_buy: u64,
                wallets_sell: WalletsData,
                amount_sell: f64,
                locktime_sell: u64,
                secret: Option<Vec<u8>>,
                secret_hash: [u8; 32]
            ) -> TradeResult<Trade> {
    let (name, exch_data_in, exch_data_out) = Self::get_fields(name, wallets_buy, amount_buy, locktime_buy,
                                                                     wallets_sell, amount_sell, locktime_sell,
                                                                     secret_hash)?;
        Ok(Trade {
            version: TRADE_VERSION,
            id: name,
            contract: Contract::Fulfiller(
                ContractStageFulfiller::Undef(
                    ContractParams {
                        exchange_data_coin_buy: exch_data_in,
                        exchange_data_coin_sell: exch_data_out,
                        secret: secret
                    }
                )
            )
        })
    }

    fn get_fields(name : String,
                wallets_buy : WalletsData,
                amount_buy : f64,
                locktime_buy : u64,
                wallets_sell : WalletsData,
                amount_sell : f64,
                locktime_sell : u64,
                secret_hash: [u8; 32]
            ) -> TradeResult<(String, ExchangeData, ExchangeData)> {
        let exch_data_in = match wallets_buy {
            WalletsData::WBtc(wallets_data) => {
                let payload_inititator = match wallets_data.initiator.payload {
                    bitcoin::util::address::Payload::WitnessProgram(ref wp) => {
                        match wp.version().to_u8() {
                            0 => wp.program(),
                            _ => return Err(TradeError::UnsupportedAddress {
                                    addr: Address::Btc(wallets_data.initiator.clone()),
                                    comment: "2At this time supported only witness p2pkh Bitcoin addresses".into()
                                })
                        }
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Btc(wallets_data.initiator),
                            comment: "3At this time supported only witness p2pkh Bitcoin addresses".into()
                        })
                }.to_vec();
                let payload_fulfiller = match wallets_data.fulfiller.payload {
                    bitcoin::util::address::Payload::WitnessProgram(ref wp) => {
                        match wp.version().to_u8() {
                            0 => wp.program(),
                            _ => return Err(TradeError::UnsupportedAddress {
                                    addr: Address::Btc(wallets_data.initiator.clone()),
                                    comment: "4At this time supported only witness p2pkh Bitcoin addresses".into()
                                })
                        }
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Btc(wallets_data.fulfiller),
                            comment: "5At this time supported only witness p2pkh Bitcoin addresses".into()
                        })
                }.to_vec();
                ExchangeData::Btc(
                    ExchangeDataBtc {
                        wallets : WalletsBtc {
                            initiator : wallets_data.initiator.clone(),
                            fulfiller : wallets_data.fulfiller.clone()
                        },
                        amount : amount_buy,
                        locktime : locktime_buy,
                        script : {
                            bitcoin::blockdata::script::Script::from(Self::get_script_vec(secret_hash.clone().to_vec(),
                                                                                       locktime_buy,
                                                                                       payload_inititator,
                                                                                       payload_fulfiller))
                        }
                    }
                )
            },
            WalletsData::WZec(wallets_data) => {
                let payload_inititator = match wallets_data.initiator.payload {
                    bitcoin_zcash::util::address::Payload::PubkeyHash(ref hash) => {
                        hash.as_bytes()
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Zec(wallets_data.initiator),
                            comment: "6At this time supported only \"t\" p2pkh Zcash addresses".into()
                        })
                }.to_vec();
                let payload_fulfiller = match wallets_data.fulfiller.payload {
                    bitcoin_zcash::util::address::Payload::PubkeyHash(ref hash) => {
                        hash.as_bytes()
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Zec(wallets_data.fulfiller),
                            comment: "7At this time supported only \"t\" p2pkh Zcash addresses".into()
                        })
                }.to_vec();
                ExchangeData::Zec(
                    ExchangeDataZec {
                        wallets : WalletsZec {
                            initiator : wallets_data.initiator.clone(),
                            fulfiller : wallets_data.fulfiller.clone()
                        },
                        amount : amount_buy,
                        locktime : locktime_buy,
                        script : {
                            bitcoin_zcash::blockdata::script::Script::from(Self::get_script_vec(secret_hash.clone().to_vec(),
                                                       locktime_buy,
                                                       payload_inititator,
                                                       payload_fulfiller))
                        }
                    }
                )
            }
        };
        let exch_data_out = match wallets_sell {
            WalletsData::WBtc(wallets_data) => {
                let payload_inititator = match wallets_data.initiator.payload {
                    bitcoin::util::address::Payload::WitnessProgram(ref wp) => {
                        match wp.version().to_u8() {
                            0 => wp.program(),
                            _ => return Err(TradeError::UnsupportedAddress {
                                    addr: Address::Btc(wallets_data.initiator.clone()),
                                    comment: "8At this time supported only witness p2pkh Bitcoin addresses".into()
                                })
                        }
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Btc(wallets_data.initiator),
                            comment: "9At this time supported only witness p2pkh Bitcoin addresses".into()
                        })
                }.to_vec();
                let payload_fulfiller = match wallets_data.fulfiller.payload {
                    bitcoin::util::address::Payload::WitnessProgram(ref wp) => {
                        match wp.version().to_u8() {
                            0 => wp.program(),
                            _ => return Err(TradeError::UnsupportedAddress {
                                    addr: Address::Btc(wallets_data.initiator.clone()),
                                    comment: "10At this time supported only witness p2pkh Bitcoin addresses".into()
                                })
                        }
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Btc(wallets_data.fulfiller),
                            comment: "11At this time supported only witness p2pkh Bitcoin addresses".into()
                        })
                }.to_vec();
                ExchangeData::Btc(
                ExchangeDataBtc {
                    wallets : WalletsBtc {
                        initiator : wallets_data.initiator.clone(),
                        fulfiller : wallets_data.fulfiller.clone()
                    },
                    amount : amount_sell,
                    locktime : locktime_sell,
                    script : {
                        bitcoin::blockdata::script::Script::from(Self::get_script_vec(secret_hash.clone().to_vec(),
                                                   locktime_sell,
                                                   payload_fulfiller,
                                                   payload_inititator))
                    }


                    }
                )
            },
            WalletsData::WZec(wallets_data) => {
                let payload_inititator = match wallets_data.initiator.payload {
                    bitcoin_zcash::util::address::Payload::PubkeyHash(ref hash) => {
                        hash.as_bytes()
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Zec(wallets_data.fulfiller),
                            comment: "At this time supported only \"t\" p2pkh Zcash addresses".into()
                        })
                }.to_vec();
                let payload_fulfiller = match wallets_data.fulfiller.payload {
                    bitcoin_zcash::util::address::Payload::PubkeyHash(ref hash) => {
                        hash.as_bytes()
                    },
                    _ => return Err(TradeError::UnsupportedAddress {
                            addr: Address::Zec(wallets_data.fulfiller),
                            comment: "At this time supported only \"t\" p2pkh Zcash addresses".into()
                        })
                }.to_vec();
                ExchangeData::Zec(
                ExchangeDataZec {
                    wallets : WalletsZec {
                        initiator : wallets_data.initiator.clone(),
                        fulfiller : wallets_data.fulfiller.clone()
                    },
                    amount : amount_sell,
                    locktime : locktime_sell,
                    script : {
                        bitcoin_zcash::blockdata::script::Script::from(Self::get_script_vec(secret_hash.clone().to_vec(),
                                                   locktime_sell,
                                                   payload_fulfiller,
                                                   payload_inititator))
                    }
                }
                )
            }
        };
        Ok((name, exch_data_in, exch_data_out))
    }

    /// Init trade
    pub fn init(&mut self, rpc_btc : & exonum_bitcoinrpc_zec_exp::Client, rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<()> {
        use swas::ExchangeData::{Btc, Zec};
        use swas::Contract::{Initiator, Fulfiller};
        let mut newtrade = self.clone();
        match &self.contract {
            Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Undef(ref params) => {
                        match params.exchange_data_coin_buy {
                        Btc(ref exdata) => {
                            let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                            match rpc_btc.importaddress(&script_addr, format!("script_swas_{}", script_addr).as_ref(), false, false) {
                                Ok(_) => {},
                                Err(e) => match e {
                                    exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                    _ => return Err(TradeError::RpcError{
                                        call: format!("rpc_btc.importaddress({}, ...)", script_addr).into(),
                                        rpc_err: e
                                    })
                                }
                            }
                        },
                        Zec(ref exdata) => {
                            let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                            match rpc_zec.importaddress_zcash(&script_addr, "", false) {
                                Ok(_) => {},
                                Err(e) => match e {
                                    exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                    _ => return Err(TradeError::RpcError{
                                        call: format!("rpc_zec.importaddress_zcash({}, \"\", false)", script_addr).into(),
                                        rpc_err: e
                                    })
                                }
                            }
                        },
                    };
                    match params.exchange_data_coin_sell {
                        Btc(ref exdata) => {
                            let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                            match rpc_btc.importaddress(&script_addr, format!("script_swas_{}", script_addr).as_ref(), false, false) {
                                Ok(_) => {},
                                Err(e) => match e {
                                    exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                    _ => return Err(TradeError::RpcError{
                                        call: format!("rpc_btc.importaddress({}, ...)", script_addr).into(),
                                        rpc_err: e
                                    })
                                }
                            }
                        },
                        Zec(ref exdata) => {
                            let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                            match rpc_zec.importaddress_zcash(&script_addr, "", false) {
                                Ok(_) => {},
                                Err(e) => match e {
                                    exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                    _ => return Err(TradeError::RpcError{
                                        call: format!("rpc_zec.importaddress_zcash({}, \"\", false)", script_addr).into(),
                                        rpc_err: e
                                    })
                                }
                            }
                        },
                    };
                    newtrade.contract = Initiator(ContractStageInitiator::Init(params.clone()));
                },
                    _ => return Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
            Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::Undef(ref params) => {
                        match params.exchange_data_coin_buy {
                            Btc(ref exdata) => {
                                let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.initiator.network).to_string());
                                match rpc_btc.importaddress(&script_addr, format!("script_swas_{}", script_addr).as_ref(), false, false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_btc.importaddress({}, ...)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                                match rpc_btc.importaddress(&format!("{}", exdata.wallets.initiator), format!("swas_{}", exdata.wallets.initiator).as_ref(), false, false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_btc.importaddress({}, ...)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                            },
                            Zec(ref exdata) => {
                                let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.initiator.network).to_string());
                                match rpc_zec.importaddress_zcash(&script_addr, "", false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_zec.importaddress_zcash({}, \"\", false)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                                match rpc_zec.importaddress_zcash(&format!("{}", exdata.wallets.initiator), "", false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_zec.importaddress_zcash({}, \"\", false)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                            },
                        };
                        match params.exchange_data_coin_sell {
                            Btc(ref exdata) => {
                                let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                match rpc_btc.importaddress(&script_addr, format!("script_swas_{}", script_addr).as_ref(), false, false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_btc.importaddress({}, ...)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                            },
                            Zec(ref exdata) => {
                                let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                match rpc_zec.importaddress_zcash(&script_addr, "", false) {
                                    Ok(_) => {},
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {},
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_zec.importaddress_zcash({}, \"\", false)", script_addr).into(),
                                            rpc_err: e
                                        })
                                    }
                                }
                            },
                        };
                        newtrade.contract = Fulfiller(ContractStageFulfiller::Init(params.clone()));
                    },
                    _ => return Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
        }
        *self = newtrade;
        Ok(())
    }

    /// Check trade state
    ///
    /// In forward direction - state incremented step by step in only one next stage
    ///
    /// In backward direction - state can roll back in several stages
    pub fn check(&mut self, min_confirmations: u64, rpc_btc : & exonum_bitcoinrpc_zec_exp::Client, rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Stage> {
        let mut newtrade : Trade;
        newtrade = self.clone();
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    // Waiting for the Initiator to send money to contract script.
                    ContractStageInitiator::Init(params) => {
                            newtrade.contract = Self::check_initiator_funded(params, true, min_confirmations, rpc_btc, rpc_zec)?;
                        },
                    // Initiator sent money to Contract script
                    // Waiting for the Fulfiller to send money to contract script.
                    ContractStageInitiator::Funded(ref params) => {
                            newtrade.contract = match Self::check_refunded(params, true, false, min_confirmations, rpc_btc, rpc_zec) {
                                Ok(contract) => {
                                    match contract {
                                        Contract::Initiator(stage) => {
                                            match stage {
                                                ContractStageInitiator::Funded(ref params) => {
                                                    Self::check_fulfiller_funded(&params.clone(), true, min_confirmations, rpc_btc, rpc_zec)?
                                                }
                                                ContractStageInitiator::Refunded(params) => {
                                                    Contract::Initiator(ContractStageInitiator::Refunded(params))
                                                },
                                                _ => {
                                                    unreachable!()
                                                }
                                            }
                                        },
                                        _ => {
                                            unreachable!()
                                        }
                                    }
                                },
                                Err(e) => return Err(e)
                            };
                    },
                    // Fulfiller sent money to Contract script
                    // Waiting for the Initiator to send money from contract script to his own address.
                    ContractStageInitiator::FulfillerFunded(ref params) => {
                        newtrade.contract = match Self::check_refunded(params, true, true, min_confirmations, rpc_btc, rpc_zec) {
                            Ok(contract) => {
                                match contract {
                                    Contract::Initiator(stage) => {
                                        match stage {
                                            ContractStageInitiator::FulfillerFunded(params) => {
                                                Self::check_initiator_redeemed(params, true, min_confirmations, rpc_btc, rpc_zec)?
                                            }
                                            ContractStageInitiator::Funded(params) => {
                                                Contract::Initiator(ContractStageInitiator::Funded(params))
                                            },
                                            ContractStageInitiator::Refunded(params) => {
                                                Contract::Initiator(ContractStageInitiator::Refunded(params))
                                            },
                                            _ => {
                                                unreachable!()
                                            }
                                        }
                                    },
                                    _ => {
                                        unreachable!()
                                    }
                                }
                            },
                            Err(e) => return Err(e)
                        };
                    },
                    // Initiator sent money from Contract script to his own address.
                    // Trade done
                    ContractStageInitiator::Complete(_) => {},
                    ContractStageInitiator::Refunded(_) => {},
                    ContractStageInitiator::Undef(_) => {},
                }
            },
            Contract::Fulfiller(ref stage) => {
                match stage {
                    // Waiting for the Initiator to send money to contract script.
                    ContractStageFulfiller::Init(ref params) => {
                        newtrade.contract = Self::check_initiator_funded(params, false, min_confirmations, rpc_btc, rpc_zec)?;
                    },
                    // Initiator sent money to Contract script
                    // Waiting for the Fulfiller to send money to contract script.
                    ContractStageFulfiller::InitiatorFunded(params) => {
                        newtrade.contract = Self::check_fulfiller_funded(&params, false, min_confirmations, rpc_btc, rpc_zec)?;
                    },
                    // Fulfiller sent money to Contract script
                    // Waiting for the Initiator to redeem.
                    ContractStageFulfiller::Funded(ref params) => {
                        newtrade.contract = match Self::check_refunded(params, false, false, min_confirmations, rpc_btc, rpc_zec) {
                            Ok(contract) => {
                                match contract {
                                    Contract::Fulfiller(stage) => {
                                        match stage {
                                            ContractStageFulfiller::Funded(params) => {
                                                Self::check_initiator_redeemed(params, false, min_confirmations, rpc_btc, rpc_zec)?
                                            },
                                            ContractStageFulfiller::Refunded(params) => {
                                                Contract::Fulfiller(ContractStageFulfiller::Refunded(params))
                                            },
                                            _ => {
                                                unreachable!();
                                            }
                                        }
                                    },
                                    _ => {
                                        unreachable!();
                                    }
                                }
                            },
                            Err(e) => return Err(e)
                        };

                    },
                    // Initiator redeemed contract.
                    // Extract secret and redeem own contract.
                    ContractStageFulfiller::InitiatorRedeemed(ref params) => {
                        newtrade.contract = Self::check_fulfiller_redeemed(params.clone(), min_confirmations, rpc_btc, rpc_zec)?;
                    },
                    ContractStageFulfiller::Complete(_) => {},
                    ContractStageFulfiller::Refunded(_) => {},
                    ContractStageFulfiller::Undef(_) => {},
                }
            },
        };
        *self = newtrade;
        Ok(self.get_stage())
    }

    /// Send funds from initiator to contract p2sh address
    pub fn fund(&mut self,
            redeem_fee_sat: u32,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Txid> {
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Init(ref params) => {
                        match params.exchange_data_coin_sell {
                            ExchangeData::Btc(ref exdata) => {
                                // Send funds
                                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.initiator.network).to_string());
                                let amount = ((exdata.amount + (redeem_fee_sat as f64 / SATOSHI_AMOUNT)) * SATOSHI_AMOUNT).round() / SATOSHI_AMOUNT;
                                match rpc_btc.sendtoaddress(&addr, amount.to_string().as_ref()) {
                                    Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                                            let mut txid = txid.from_hex().unwrap();
                                            txid.reverse();
                                            txid
                                        }.as_slice()))),
                                    Err(e) => Err(TradeError::RpcError{
                                        call: format!("rpc_btc.sendtoaddress({}, {})", addr, amount).into(),
                                        rpc_err: e
                                    })
                                }
                            },
                            ExchangeData::Zec(ref exdata) => {
                                // Send funds
                                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.initiator.network).to_string());
                                let amount = ((exdata.amount + (redeem_fee_sat as f64 / SATOSHI_AMOUNT)) * SATOSHI_AMOUNT).round() / SATOSHI_AMOUNT;
                                match rpc_zec.sendtoaddress(&addr, amount.to_string().as_ref()) {
                                    Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                                            let mut txid = txid.from_hex().unwrap();
                                            txid.reverse();
                                            txid
                                        }.as_slice()))),
                                    Err(e) => Err(TradeError::RpcError{
                                        call: format!("rpc_zec.sendtoaddress({}, {})", addr, amount).into(),
                                        rpc_err: e
                                    })
                                }
                            },
                        }
                    }
                    _ => Err(TradeError::InvalidStage(self.get_stage()))
                }
            },
            Contract::Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::InitiatorFunded(ref params) => {
                        match params.exchange_data_coin_buy {
                            ExchangeData::Btc(ref exdata) => {
                                // Send funds
                                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                let amount = ((exdata.amount + (redeem_fee_sat as f64 / SATOSHI_AMOUNT)) * SATOSHI_AMOUNT).round() / SATOSHI_AMOUNT;
                                match rpc_btc.sendtoaddress(&addr, &amount.to_string()) {
                                    Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                                            let mut txid = txid.from_hex().unwrap();
                                            txid.reverse();
                                            txid
                                        }.as_slice()))),
                                    Err(e) => Err(TradeError::RpcError{
                                        call: format!("rpc_btc.sendtoaddress({}, {})", addr, amount).into(),
                                        rpc_err: e
                                    })
                                }
                            },
                            ExchangeData::Zec(ref exdata) => {
                                // Check if fulfiller redeemed
                                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                let amount = ((exdata.amount + (redeem_fee_sat as f64 / SATOSHI_AMOUNT)) * SATOSHI_AMOUNT).round() / SATOSHI_AMOUNT;
                                match rpc_zec.sendtoaddress(&addr, &amount.to_string()) {
                                    Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                                            let mut txid = txid.from_hex().unwrap();
                                            txid.reverse();
                                            txid
                                        }.as_slice()))),
                                    Err(e) => Err(TradeError::RpcError{
                                        call: format!("rpc_zec.sendtoaddress({}, {})", addr, amount).into(),
                                        rpc_err: e
                                    })
                                }
                            },
                        }
                    },
                    _ => Err(TradeError::InvalidStage(self.get_stage()))
                }
            },
        }
    }


    /// Refund (initiator or fulfiller, depending owner role)
    pub fn refund(&mut self,
        min_confirmations: u64,
        rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
        rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Txid> {
        self.check(min_confirmations, rpc_btc, rpc_zec)?;
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Funded(ref params) => Self::refund_initiator(params, min_confirmations, rpc_btc, rpc_zec),
                    ContractStageInitiator::FulfillerFunded(ref params) => Self::refund_initiator(params, min_confirmations, rpc_btc, rpc_zec),
                    _ => Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
            Contract::Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::Funded(ref params) => Self::refund_fulfiller(params, min_confirmations, rpc_btc, rpc_zec),
                    _ => Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
        }
    }

    // Send funds from inner contract p2sh to initiator address
    pub fn redeem(&mut self,
            fee_sat: u64,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Txid> {
                use swas::ExchangeData::{Btc, Zec};
        self.check(min_confirmations, rpc_btc, rpc_zec)?;
        let mut result;
        result = self.in_stages_fulfiller::<_, Txid>(|params|
            match &params.secret {
                Some(_) => {
                    match params.exchange_data_coin_sell {
                        Btc(ref exdata) => {
                            let transaction_raw = Self::create_redeem_tx_btc(&exdata.script, &exdata.wallets.fulfiller, fee_sat, min_confirmations, params.secret.clone().unwrap(), rpc_btc)?;
                            let transaction_raw = self::bitcoin::network::serialize::serialize::<BtcTransaction>(&transaction_raw).unwrap();
                            match rpc_btc.sendrawtransaction(&transaction_raw.to_hex()) {
                                Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                                        let mut txid = txid.from_hex().unwrap();
                                        txid.reverse();
                                        txid
                                    }.as_slice()))),
                                Err(e) => Err(TradeError::RpcError{
                                    call: format!("5rpc_btc.sendrawtransaction({})", transaction_raw.to_hex()).into(),
                                    rpc_err: e
                                })
                            }
                        }
                        Zec(ref exdata) => {
                            let transaction_raw = Self::create_redeem_tx_zec(&exdata.script, &exdata.wallets.fulfiller, fee_sat, min_confirmations, params.secret.clone().unwrap(), rpc_zec)?;
                            let transaction_raw = self::bitcoin_zcash::network::serialize::serialize::<ZecTransaction>(&transaction_raw).unwrap();
                            match rpc_zec.sendrawtransaction(&transaction_raw.to_hex()) {
                                Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                                        let mut txid = txid.from_hex().unwrap();
                                        txid.reverse();
                                        txid
                                    }.as_slice()))),
                                Err(e) => Err(TradeError::RpcError{
                                    call: format!("rpc_zec.sendrawtransaction({})", transaction_raw.to_hex()).into(),
                                    rpc_err: e
                                })
                            }
                        }
                    }
                },
                None => {
                    Err(TradeError::Other("Script not founded".into()))
                }
            }
        );
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::FulfillerFunded(ref params) => {
                        match self.funds_check(min_confirmations, fee_sat, rpc_btc, &rpc_zec) {
                            Ok(_funds) => {
                                match params.exchange_data_coin_buy {
                                    Btc(ref exdata) => {
                                        let transaction_raw = Self::create_redeem_tx_btc(&exdata.script, &exdata.wallets.initiator, fee_sat, min_confirmations, params.secret.clone().unwrap(), rpc_btc)?;
                                        let transaction_raw = self::bitcoin::network::serialize::serialize::<BtcTransaction>(&transaction_raw).unwrap();
                                        result = match rpc_btc.sendrawtransaction(&transaction_raw.to_hex()) {
                                            Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                                                    let mut txid = txid.from_hex().unwrap();
                                                    txid.reverse();
                                                    txid
                                                }.as_slice()))),
                                            Err(e) => Err(TradeError::RpcError{
                                                call: format!("1rpc_btc.sendrawtransaction({})", transaction_raw.to_hex()).into(),
                                                rpc_err: e
                                            })
                                        };
                                    },
                                    Zec(ref exdata) => {
                                        let transaction_raw = Self::create_redeem_tx_zec(&exdata.script, &exdata.wallets.initiator, fee_sat, min_confirmations, params.secret.clone().unwrap(), rpc_zec)?;
                                        let transaction_raw = self::bitcoin_zcash::network::serialize::serialize::<ZecTransaction>(&transaction_raw).unwrap();
                                        result = match rpc_zec.sendrawtransaction(&transaction_raw.to_hex()) {
                                            Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                                                    let mut txid = txid.from_hex().unwrap();
                                                    txid.reverse();
                                                    txid
                                                }.as_slice()))),
                                            Err(e) => Err(TradeError::RpcError{
                                                call: format!("rpc_zec.sendrawtransaction({})", transaction_raw.to_hex()).into(),
                                                rpc_err: e
                                            })
                                        };
                                    },
                                }
                            },
                            Err(e) => result = Err(e)
                        }
                    },
                    ContractStageInitiator::Refunded(_) => result = Err(TradeError::AlreadyRedeemed),
                    ContractStageInitiator::Complete(_) => result = Err(TradeError::AlreadyRedeemed),
                    _ => result = Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
            _ => {}
        };
        result
    }

    /// Collect and return amount of funds, collected on "buy" p2wsh contract address
    pub fn get_unredeemed_amount(&self,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<f64> {
        use swas::ExchangeData::{Btc, Zec};
        let mut is_btc = false;
        let mut addr_btc = BtcAddress::from_str("mqnARwaJVfKrE9RDdiQvw5aajk7zgqFbg1").unwrap();
        let mut addr_zec = ZecAddress::from_str("tmCazwAKSjfi89CLgT2PDBG3MfpHGTCNagP").unwrap();
        match self.in_stages_initiator::<_, ()>(|params| {
            match &params.exchange_data_coin_buy {
                Btc(ref exdata) => {
                    is_btc = true;
                    addr_btc = BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network);
                    Ok(())
                },
                Zec(ref exdata) => {
                    addr_zec = ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network);
                    Ok(())
                },
            }
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        match self.in_stages_fulfiller::<_, ()>(|params| {
            match &params.exchange_data_coin_sell {
                Btc(ref exdata) => {
                    is_btc = true;
                    addr_btc = BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network);
                    Ok(())
                },
                Zec(ref exdata) => {
                    addr_zec = ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network);
                    Ok(())
                },
            }
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        if is_btc == true {
            Ok(Self::unspent_index_btc(&addr_btc, min_confirmations, rpc_btc).unwrap().amount_total)
        } else {
            Ok(Self::unspent_index_zec(&addr_zec, min_confirmations, rpc_zec).unwrap().amount_total)
        }
    }

    /// Get Trade ID
    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    /// Set Trade ID
    pub fn set_id(&mut self, s: String) {
        self.id = s;
    }

    /// Get current trade stage (checking does not performed)
    pub fn get_stage(&self) -> Stage {
        use self::Stage::{*};
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Init(_) => InitiatorInit,
                    ContractStageInitiator::Funded(_) => InitiatorFunded,
                    ContractStageInitiator::FulfillerFunded(_) => InitiatorFulfillerFunded,
                    ContractStageInitiator::Complete(_) => InitiatorComplete,
                    ContractStageInitiator::Refunded(_) => InitiatorRefunded,
                    _ => {InitiatorUndef},
                }
            },
            Contract::Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::Init(_) => FulfillerInit,
                    ContractStageFulfiller::InitiatorFunded(_) => FulfillerInitiatorFunded,
                    ContractStageFulfiller::Funded(_) => FulfillerFunded,
                    ContractStageFulfiller::InitiatorRedeemed(_) => FulfillerInitiatorRedeemed,
                    ContractStageFulfiller::Complete(_) => FulfillerComplete,
                    ContractStageFulfiller::Refunded(_) => FulfillerRefunded,
                    _ => {FulfillerUndef},
                }
            }
        }
    }

    /// Get currency which coins selled
    pub fn get_currency_sell(&self) -> Currency {
        match self.get_currency_buy() {
            Currency::Bitcoin => Currency::Zcash,
            Currency::Zcash => Currency::Bitcoin
        }
    }

    /// Get currency which coins bought
    pub fn get_currency_buy(&self) -> Currency {
        use self::Currency::{*};
        let mut result = Bitcoin;
        match self.in_stages_initiator::<_, ()>(|params| {
            match &params.exchange_data_coin_buy {
                ExchangeData::Btc(_) => result = Bitcoin,
                ExchangeData::Zec(_) => result = Zcash,
            };
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        match self.in_stages_fulfiller::<_, ()>(|params| {
            match params.exchange_data_coin_sell {
                ExchangeData::Btc(_) => result = Bitcoin,
                ExchangeData::Zec(_) => result = Zcash,
            };
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        result
    }

    /// Get own role in trade
    pub fn get_role(&self) -> Role {
        match self.contract {
            Contract::Initiator(_) => {
                Role::Initiator
            },
            Contract::Fulfiller(_) => {
                Role::Fulfiller
            }
        }
    }

    /// Get secret vector (if known)
    pub fn get_secret(&self) -> Option<Vec<u8>> {
        let mut result = None;
        match self.in_stages_initiator::<_, ()>(|params| {
            result = params.secret.clone();
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        match self.in_stages_fulfiller::<_, ()>(|params| {
            result = params.secret.clone();
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        result
    }

    /// Get amount to buy
    pub fn get_amount_buy(&self) -> f64 {
        let mut result = 0.0;
        match self.contract {
            Contract::Initiator(_) => {
                match self.in_stages_initiator::<_, ()>(|params| {
                    match params.exchange_data_coin_buy {
                        ExchangeData::Btc(ref exdata) => result = exdata.amount,
                        ExchangeData::Zec(ref exdata) => result = exdata.amount,
                    }
                    Ok(())
                }) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            },
            Contract::Fulfiller(_) => {
                match self.in_stages_fulfiller::<_, ()>(|params| {
                    match params.exchange_data_coin_sell {
                        ExchangeData::Btc(ref exdata) => result = exdata.amount,
                        ExchangeData::Zec(ref exdata) => result = exdata.amount,
                    }
                    Ok(())
                }) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
        };
        result
    }

    /// Get amount to sell
    pub fn get_amount_sell(&self) -> f64 {
        let mut result = 0.0;
        match self.contract {
            Contract::Initiator(_) => {
                match self.in_stages_initiator::<_, ()>(|params| {
                    match params.exchange_data_coin_sell {
                        ExchangeData::Btc(ref exdata) => result = exdata.amount,
                        ExchangeData::Zec(ref exdata) => result = exdata.amount,
                    }
                    Ok(())
                }) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            },
            Contract::Fulfiller(_) => {
                match self.in_stages_fulfiller::<_, ()>(|params| {
                    match params.exchange_data_coin_buy {
                        ExchangeData::Btc(ref exdata) => result = exdata.amount,
                        ExchangeData::Zec(ref exdata) => result = exdata.amount,
                    }
                    Ok(())
                }) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
        };
        result
    }

    /// Export in raw format without secret
    pub fn export(&self) -> Vec<u8> {
        self.without_secret()
            .change_role_and_reset(Role::Fulfiller)
            .concensus_encode()
    }

    /// Import from raw format (only as fulfiller)
    pub fn import(v: Vec<u8>) -> TradeResult<Trade> {
        let trade = match Self::concensus_decode(v) {
            Ok(t) => t,
            Err(e) => return Err(TradeError::NetworkConsensusError(e))
        };
        match &trade.contract {
            Contract::Initiator(_) => return Err(TradeError::InvalidRole(Role::Initiator)),
            _ => {}
        }
        Ok(trade.change_stage(Stage::FulfillerUndef))
    }

    pub fn concensus_encode(&self) -> Vec<u8> {
        bitcoin::network::serialize::serialize(self).unwrap()
    }

    pub fn concensus_decode(v: Vec<u8>) -> Result<Trade,  bitcoin::network::serialize::Error> {
        let r: Self = bitcoin::network::serialize::deserialize(&v.as_slice())?;
        Ok(r)
    }

    fn get_script_vec(secret_hash : Vec<u8>,
                    locktime : u64,
                    wall_to : Vec<u8>,
                    wall_from : Vec<u8>) -> Vec<u8> {
        use swas::bitcoin::blockdata::opcodes::All::{*};
        bitcoin::blockdata::script::Builder::new()
            .push_opcode(OP_0NOTEQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(secret_hash.as_slice())
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(wall_to.as_slice())
            .push_opcode(OP_ELSE)
            .push_int(locktime as i64)
            .push_opcode(OP_CHECKLOCKTIMEVERIFY)
            .push_opcode(OP_DROP)
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(wall_from.as_slice())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script().to_bytes()
    }

    fn refund_initiator(params: &ContractParams,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Txid> {
        match params.exchange_data_coin_sell {
            ExchangeData::Btc(ref exdata) => {
                let current_blockcount = match rpc_btc.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.getblockcount()").into(),
                        rpc_err: e
                    })
                };
                if current_blockcount < (exdata.locktime) {
                    return Err(TradeError::RefundAttemptTooEarly {
                        current_blocknum: current_blockcount,
                        expected_blocknum: exdata.locktime
                    })
                }
                let transaction_raw = Self::create_refund_tx_btc(&exdata.script, exdata.locktime, &exdata.wallets.initiator, 1000, min_confirmations, rpc_btc)?;
                let transaction_raw = self::bitcoin::network::serialize::serialize::<BtcTransaction>(&transaction_raw).unwrap();
                match rpc_btc.sendrawtransaction(&transaction_raw.to_hex()) {
                    Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                            let mut txid = txid.from_hex().unwrap();
                            txid.reverse();
                            txid
                        }.as_slice()))),
                    Err(e) => Err(TradeError::RpcError{
                        call: format!("2rpc_btc.sendrawtransaction({})", &transaction_raw.to_hex()).into(),
                        rpc_err: e
                    })
                }
            },
            ExchangeData::Zec(ref exdata) => {
                let current_blockcount = match rpc_zec.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.getblockcount()").into(),
                        rpc_err: e
                    })
                };
                if current_blockcount < (exdata.locktime) {
                    return Err(TradeError::RefundAttemptTooEarly {
                        current_blocknum: current_blockcount,
                        expected_blocknum: exdata.locktime
                    })
                }
                let transaction_raw = Self::create_refund_tx_zec(&exdata.script, exdata.locktime, &exdata.wallets.initiator, 1000, current_blockcount, min_confirmations, rpc_zec)?;
                let transaction_raw = self::bitcoin_zcash::network::serialize::serialize::<ZecTransaction>(&transaction_raw).unwrap();
                match rpc_zec.sendrawtransaction(&transaction_raw.to_hex()) {
                    Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                            let mut txid = txid.from_hex().unwrap();
                            txid.reverse();
                            txid
                        }.as_slice()))),
                    Err(e) => Err(TradeError::RpcError{
                        call: format!("rpc_zec.sendrawtransaction({})", &transaction_raw.to_hex()).into(),
                        rpc_err: e
                    })
                }
            },
        }
    }

    fn refund_fulfiller(params: &ContractParams,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Txid> {
        match params.exchange_data_coin_buy {
            ExchangeData::Btc(ref exdata) => {
                let current_blockcount = match rpc_btc.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(e) =>  return Err(TradeError::RpcError{
                        call: format!("rpc_btc.getblockcount()").into(),
                        rpc_err: e
                    })
                };
                if current_blockcount < (exdata.locktime) {
                    return Err(TradeError::RefundAttemptTooEarly {
                        current_blocknum: current_blockcount,
                        expected_blocknum: exdata.locktime
                    })
                }
                let transaction_raw = Self::create_refund_tx_btc(&exdata.script, exdata.locktime, &exdata.wallets.fulfiller, 1000, min_confirmations, rpc_btc)?;
                let transaction_raw = self::bitcoin::network::serialize::serialize::<BtcTransaction>(&transaction_raw).unwrap();
                match rpc_btc.sendrawtransaction(&transaction_raw.to_hex()) {
                    Ok(txid) => Ok(Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                            let mut txid = txid.from_hex().unwrap();
                            txid.reverse();
                            txid
                        }.as_slice()))),
                    Err(e) => Err(TradeError::RpcError{
                        call: format!("4rpc_btc.sendrawtransaction({})", &transaction_raw.to_hex()).into(),
                        rpc_err: e
                    })
                }
            },
            ExchangeData::Zec(ref exdata) => {
                let current_blockcount = match rpc_zec.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.getblockcount()").into(),
                        rpc_err: e
                    })
                };
                if current_blockcount < (exdata.locktime) {
                    return Err(TradeError::RefundAttemptTooEarly {
                        current_blocknum: current_blockcount,
                        expected_blocknum: exdata.locktime
                    })
                }
                let transaction_raw = Self::create_refund_tx_zec(&exdata.script, exdata.locktime, &exdata.wallets.fulfiller, 1000, current_blockcount, min_confirmations, rpc_zec)?;
                let transaction_raw = self::bitcoin_zcash::network::serialize::serialize::<ZecTransaction>(&transaction_raw).unwrap();
                match rpc_zec.sendrawtransaction(&transaction_raw.to_hex()) {
                    Ok(txid) => Ok(Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                            let mut txid = txid.from_hex().unwrap();
                            txid.reverse();
                            txid
                        }.as_slice()))),
                    Err(e) => Err(TradeError::RpcError{
                        call: format!("rpc_zec.sendrawtransaction({})", &transaction_raw.to_hex()).into(),
                        rpc_err: e
                    })
                }
            },
        }
    }

    /// Check funds on Initiator's side in contract's p2sh address
    fn funds_check(&self,
            min_confirmations: u64,
            fee_sat: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client)  -> TradeResult<f64> {
    use swas::ExchangeData::{Btc, Zec};
        let redeemed_funds;
        let needed;
        let addr_to_err;
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::FulfillerFunded(ref params) => {
                        match params.exchange_data_coin_buy {
                            Btc(ref exdata) => {
                                needed = exdata.amount;
                                // Receive funds
                                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                redeemed_funds = match rpc_btc.getreceivedbyaddress(&addr, min_confirmations) {
                                    Ok(answer) => answer,
                                    Err(e) => return Err(TradeError::RpcError{
                                        call: format!("rpc_btc.getreceivedbyaddress({},{})", addr, min_confirmations).into(),
                                        rpc_err: e
                                    })
                                };
                                addr_to_err = Address::Btc(BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network));
                            },
                            Zec(ref exdata) => {
                                needed = exdata.amount;
                                // Receive funds
                                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                redeemed_funds = match rpc_zec.getreceivedbyaddress(&addr, min_confirmations) {
                                    Ok(answer) => answer,
                                    Err(e) => return Err(TradeError::RpcError{
                                        call: format!("rpc_zec.getreceivedbyaddress({},{})", addr, min_confirmations).into(),
                                        rpc_err: e
                                    })
                                };
                                addr_to_err = Address::Zec(ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network))
                            },
                        };
                    }
                    _ => return Err(TradeError::InvalidStage(self.get_stage())),
                }
            },
            _ => return Err(TradeError::InvalidRole(self.get_role())),
        };
        let needed = (needed + (fee_sat as f64 / SATOSHI_AMOUNT) * SATOSHI_AMOUNT).round() / SATOSHI_AMOUNT;
        if redeemed_funds >= needed {
            Ok(redeemed_funds)
        }else {
            Err(TradeError::TooSmallBalance{
                addr: addr_to_err,
                current: redeemed_funds,
                expected: needed + (fee_sat as f64 / SATOSHI_AMOUNT)
            })
        }
    }

    fn amount_tx_btc(address: & BtcAddress,
            txid: bitcoin::util::hash::Sha256dHash,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client
        ) -> TradeResult<u64> {
        // Spendable amount
        let mut amount = 0.0;
        // Collect unspended txins in contract p2sh address
        for txin in match rpc_btc.listunspent(min_confirmations as u32, 9999999, &[&address.to_string()]) {
                    Ok(outputs) => outputs,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.listunspent({}, {}, [{}])", min_confirmations, 9999999, &address.to_string()).into(),
                        rpc_err: e
                    })
                } {
            // Spent tx
            let txin_tx: BtcTransaction = match rpc_btc.getrawtransaction(&txin.txid) {
                Ok(raw_prev_tx) => {
                    let hex_tx = bitcoin::util::misc::hex_bytes(&raw_prev_tx).unwrap();
                    bitcoin::network::serialize::deserialize(&hex_tx).unwrap()
                },
                Err(e) => return Err(TradeError::RpcError{
                    call: format!("rpc_btc.getrawtransaction({})", &txin.txid).into(),
                    rpc_err: e
                })
            };
            if txid == txin_tx.txid() {
                amount+= txin.amount;
            }
        }
        Ok((amount * SATOSHI_AMOUNT) as u64)
    }

    fn unspent_index_btc(address: & BtcAddress,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client
        ) -> TradeResult<UnspentBtc> {
        let mut txins = Vec::<bitcoin::blockdata::transaction::TxIn>::new();
        // Spendable amount
        let mut amount = 0.0;
        let mut input_amounts = Vec::new();
        // Collect unspended txins in contract p2sh address
        for txin in match rpc_btc.listunspent(min_confirmations as u32, 9999999, &[&address.to_string()]) {
                    Ok(outputs) => outputs,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.listunspent({}, {}, [{}])", min_confirmations, 9999999, &address.to_string()).into(),
                        rpc_err: e
                    })
                } {
            txins.push(
                bitcoin::blockdata::transaction::TxIn {
                    previous_output: bitcoin::blockdata::transaction::OutPoint {
                        txid: bitcoin::util::hash::Sha256dHash::from({
                                let mut txid = txin.txid.clone().from_hex().unwrap();
                                txid.reverse();
                                txid
                            }.as_slice()),
                        vout: txin.vout
                    },
                    script_sig: bitcoin::blockdata::script::Script::new(),
                    sequence: 0xFFFFFFFF - 1,
                    witness: Vec::new()
            });
            // Spent tx
            let txin_tx: BtcTransaction = match rpc_btc.getrawtransaction(&txin.txid) {
                Ok(raw_prev_tx) => {
                    let hex_tx = bitcoin::util::misc::hex_bytes(&raw_prev_tx).unwrap();
                    bitcoin::network::serialize::deserialize(&hex_tx).unwrap()
                },
                Err(e) => return Err(TradeError::RpcError{
                    call: format!("rpc_btc.getrawtransaction({})", &txin.txid).into(),
                    rpc_err: e
                })
            };
            input_amounts.push(txin_tx.output[txin.vout as usize].value);
            amount+= txin.amount;
        }
        Ok(UnspentBtc {
            txins: txins,
            amounts_sat: input_amounts,
            amount_total: amount
        })
    }

    fn unspent_index_zec(address: & ZecAddress,
            min_confirmations: u64,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client
        ) -> TradeResult<UnspentZec> {
        let mut txins = Vec::<bitcoin_zcash::blockdata::transaction::TxIn>::new();
        // Spendable amount
        let mut amount = 0.0;
        let mut input_amounts = Vec::new();
        // Collect unspended txins in contract p2sh address
        for txin in match rpc_zec.listunspent(min_confirmations as u32, 9999999, &[&address.to_string()]) {
                    Ok(outputs) => outputs,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.listunspent({}, {}, [{}])", min_confirmations, 9999999, &address.to_string()).into(),
                        rpc_err: e
                    })
                } {
            txins.push(
                bitcoin_zcash::blockdata::transaction::TxIn {
                    previous_output: bitcoin_zcash::blockdata::transaction::OutPoint {
                        txid: bitcoin_zcash::util::hash::Sha256dHash::from({
                                let mut txid = txin.txid.clone().from_hex().unwrap();
                                txid.reverse();
                                txid
                            }.as_slice()),
                        vout: txin.vout
                    },
                    script_sig: bitcoin_zcash::blockdata::script::Script::new(),
                    sequence: 0xFFFFFFFF - 1,
                    witness: Vec::new()
            });
            // Spent tx
            let txin_tx: ZecTransaction = match rpc_zec.getrawtransaction(&txin.txid) {
                Ok(raw_prev_tx) => {
                    let hex_tx = bitcoin_zcash::util::misc::hex_bytes(&raw_prev_tx).unwrap();
                    bitcoin_zcash::network::serialize::deserialize(&hex_tx).unwrap()
                },
                Err(e) => return Err(TradeError::RpcError{
                    call: format!("rpc_zec.getrawtransaction({})", &txin.txid).into(),
                    rpc_err: e
                })
            };
            input_amounts.push(txin_tx.output[txin.vout as usize].value);
            amount+= txin.amount;
        }
        Ok(UnspentZec {
            txins: txins,
            amounts_sat: input_amounts,
            amount_total: amount
        })
    }

    fn create_redeem_tx_btc(script: & bitcoin::blockdata::script::Script,
            address: & BtcAddress,
            fee_sat: u64,
            min_confirmations: u64,
            secret: Vec<u8>,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<BtcTransaction> {
        use self::bitcoin::blockdata::script::Builder;
        use self::bitcoin::util::bip143::SighashComponents;

        let unspent = Self::unspent_index_btc(&BtcAddress::p2wsh(script, address.network),
                min_confirmations,
                rpc_btc)?;
        // Rawable transaction
        let mut transaction: BtcTransaction;
        // Output of the transaction
        let mut outputs = Vec::<bitcoin::blockdata::transaction::TxOut>::new();
        if ((unspent.amount_total * SATOSHI_AMOUNT) as u64) <= fee_sat {
            return Err(TradeError::TooSmallBalance{
                addr: Address::Btc(address.clone()),
                current: unspent.amount_total,
                expected: fee_sat as f64 / SATOSHI_AMOUNT
            })
        }
        outputs.push(bitcoin::blockdata::transaction::TxOut {
            value: (unspent.amount_total * SATOSHI_AMOUNT) as u64 - fee_sat,
            script_pubkey: address.script_pubkey()
        });
        transaction = BtcTransaction {
            version: 2,
            lock_time: 0,
            input: unspent.txins,
            output: outputs
        };
        let priv_key = match rpc_btc.dumpprivkey(format!("{}", address).as_ref()) {
            Ok(key) => {
                let mut priv_key = bitcoin::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                priv_key
            },
            Err(e) => return Err(TradeError::RpcError{
                call: format!("rpc_btc.dumpprivkey({})",  address).into(),
                rpc_err: e
            })
        };
        let secp = secp256k1::Secp256k1::new();
        for input_index in 0..transaction.input.len() {
            let value = Self::amount_tx_btc(&BtcAddress::p2wsh(script, address.network),
                    transaction.input[input_index].previous_output.txid.clone(),
                    min_confirmations,
                    rpc_btc)?;
            let sig_hash_bip143 = SighashComponents::new(&transaction);
            let sig_hash_bip143 = sig_hash_bip143.sighash_all(&transaction.input[input_index], &script, value);
            let msg = secp256k1::Message::from_slice(&sig_hash_bip143.to_bytes()).unwrap();
            let sk = secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap();
            let mut pub_key = secp256k1::key::PublicKey::from_secret_key(&secp, &sk).serialize();
            let mut sig_vec = secp.sign(&msg, &sk).serialize_der(&secp);
            sig_vec.push(0x01);
            let mut wd = Vec::new();
            wd.push(sig_vec);
            wd.push(pub_key.to_vec());
            wd.push(secret.as_slice().to_vec());
            wd.push(Builder::new().push_opcode(OP_TRUE).into_script().as_bytes().to_vec());
            wd.push(script.to_bytes());
            transaction.input[input_index].witness = wd;
        }
        Ok(transaction)
    }

    fn create_redeem_tx_zec(script: & bitcoin_zcash::blockdata::script::Script,
            address: & ZecAddress,
            fee_sat: u64,
            min_confirmations: u64,
            secret: Vec<u8>,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<ZecTransaction> {
        let unspent = Self::unspent_index_zec(&ZecAddress::p2sh(script, address.network),
                min_confirmations,
                rpc_zec).unwrap();
        let priv_key = match rpc_zec.dumpprivkey(format!("{}", address).as_ref()) {
            Ok(key) => {
                let mut priv_key = bitcoin_zcash::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                priv_key
            },
            Err(e) => return Err(TradeError::RpcError{
                call: format!("rpc_zec.dumpprivkey({})",  address).into(),
                rpc_err: e
            })
        };
        let current_blockcount = match rpc_zec.getblockcount() {
            Ok(blockcount) => blockcount,
            Err(e) => return Err(TradeError::RpcError{
                call: format!("rpc_zec.getblockcount()").into(),
                rpc_err: e
            })
        };
        let mut transaction: ZecTransaction;
        // Output of the transaction
        let mut outputs = Vec::<bitcoin_zcash::blockdata::transaction::TxOut>::new();
        if unspent.txins.len() == 0 {
            return Err(TradeError::NothingToSpend(Address::Zec(ZecAddress::p2sh(script, address.network))));
        }
        outputs.push(bitcoin_zcash::blockdata::transaction::TxOut {
            value: (unspent.amount_total * SATOSHI_AMOUNT) as u64 - fee_sat,
            script_pubkey: address.script_pubkey()
        });
        transaction = ZecTransaction {
            header: TxHeader::FourthAndOverwintered,
            version_group_id: 0x892F2085,
            lock_time: current_blockcount as u32,
            expiry_height: current_blockcount as u32 + 125, // TODO: calculate expiry_height
            value_balance: 0,
            shielded_spend: Vec::new(),
            shielded_output: Vec::new(),
            join_split: Vec::new(),
            input: unspent.txins,
            output: outputs,
            join_split_sig: None,
            join_split_pubkey: None,
            binding_sig: None,

        };
        let mut input_amounts = unspent.amounts_sat;
        input_amounts.reverse();
        let secp = secp256k1::Secp256k1::new();
        for input_index in 0..transaction.input.len() {
            let cur_amount = input_amounts.pop().unwrap();
            let sig_hash = transaction.signature_hash(input_index, script, 0x01, 0x00, cur_amount);
            let msg = secp256k1::Message::from_slice(sig_hash.as_bytes()).unwrap();
            let sk = secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap();
            let pub_key = secp256k1::key::PublicKey::from_secret_key(&secp, &sk);
            let mut sig_vec = secp.sign(&msg, &sk).serialize_der(&secp);
            sig_vec.push(0x01);
            let mut script_sig = bitcoin_zcash::blockdata::script::Builder::new()
               .push_slice(&sig_vec)
               .push_slice(&pub_key.serialize())
               .push_slice(&secret.as_slice())
               .push_opcode(OP_TRUE_ZEC)
               .push_slice(&mut script.to_bytes())
               .into_script();
            transaction.input[input_index].script_sig = script_sig.clone();
        }
        Ok(transaction)
    }

    fn create_refund_tx_btc(script: & bitcoin::blockdata::script::Script,
            locktime: u64,
            address: & BtcAddress,
            fee_sat: u64,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<BtcTransaction> {
        use self::bitcoin::util::bip143::SighashComponents;

        let address_p2sh = BtcAddress::p2wsh(script, address.network);
        let unspent = Self::unspent_index_btc(&address_p2sh,
                min_confirmations,
                rpc_btc).unwrap();
        if unspent.txins.len() == 0 {
            return Err(TradeError::NothingToSpend(Address::Btc(address_p2sh)));
        }
        let priv_key = match rpc_btc.dumpprivkey(format!("{}", address).as_ref()) {
            Ok(key) => {
                let mut priv_key = bitcoin::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                priv_key
            },
            Err(e) => match e {
                exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {
                    return Err(TradeError::PrivKeyNotFound(Address::Btc(address.clone())))
                },
                _ => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.dumpprivkey({})", address).into(),
                        rpc_err: e
                    })
            }
        };
        // Rawable transaction
        let mut transaction: BtcTransaction;
        // Output of the transaction
        let mut outputs = Vec::<bitcoin::blockdata::transaction::TxOut>::new();

        outputs.push(bitcoin::blockdata::transaction::TxOut {
            value: (unspent.amount_total * SATOSHI_AMOUNT) as u64 - fee_sat,
            script_pubkey: address.script_pubkey()
        });
        transaction = BtcTransaction {
            version: 2,
            lock_time: locktime as u32,
            input: unspent.txins,
            output: outputs
        };
        let secp = secp256k1::Secp256k1::new();
        for input_index in 0..transaction.input.len() {


            let value = Self::amount_tx_btc(&address_p2sh,
                    transaction.input[input_index].previous_output.txid.clone(),
                    min_confirmations,
                    rpc_btc)?;
            let sig_hash_bip143 = SighashComponents::new(&transaction);
            let sig_hash_bip143 = sig_hash_bip143.sighash_all(&transaction.input[input_index], &script, value);
            let msg = secp256k1::Message::from_slice(&sig_hash_bip143.to_bytes()).unwrap();
            let sk = secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap();
            let pub_key = secp256k1::key::PublicKey::from_secret_key(&secp, &sk).serialize();
            let mut sig_vec = secp.sign(&msg, &sk).serialize_der(&secp);
            sig_vec.push(0x01);
            let mut wd = Vec::new();
            wd.push(sig_vec);
            wd.push(pub_key.to_vec());
            wd.push(Vec::new());
            wd.push(script.to_bytes());
            transaction.input[input_index].witness = wd;
        }
        Ok(transaction)
    }

    fn create_refund_tx_zec(script: & bitcoin_zcash::blockdata::script::Script,
            locktime: u64,
            address: & ZecAddress,
            fee_sat: u64,
            current_blockcount: u64,
            min_confirmations: u64,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<ZecTransaction> {
        let address_p2sh = ZecAddress::p2sh(script, address.network);
        let unspent = Self::unspent_index_zec(&address_p2sh,
                min_confirmations,
                rpc_zec).unwrap();
        if unspent.txins.len() == 0 {
            return Err(TradeError::NothingToSpend(Address::Zec(address_p2sh)));
        }
        let priv_key = match rpc_zec.dumpprivkey(format!("{}", address).as_ref()) {
            Ok(key) => {
                let mut priv_key = bitcoin_zcash::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                priv_key
            },
            Err(e) => match e {
                exonum_bitcoinrpc_zec_exp::Error::WalletError(_) => {
                    return Err(TradeError::PrivKeyNotFound(Address::Zec(address.clone())))
                },
                _ => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.dumpprivkey({})", address).into(),
                        rpc_err: e
                    })
                }
        };
        // Rawable transaction
        let mut transaction: ZecTransaction;
        // Output of the transaction
        let mut outputs = Vec::<bitcoin_zcash::blockdata::transaction::TxOut>::new();
        outputs.push(bitcoin_zcash::blockdata::transaction::TxOut {
            value: (unspent.amount_total * SATOSHI_AMOUNT) as u64 - fee_sat,
            script_pubkey: address.script_pubkey()
        });
        transaction = ZecTransaction {
            header: TxHeader::FourthAndOverwintered,
            version_group_id: 0x892F2085,
            lock_time: locktime as u32,
            expiry_height: current_blockcount as u32 + 125, // TODO: calculate expiry_height
            value_balance: 0,
            shielded_spend: Vec::new(),
            shielded_output: Vec::new(),
            join_split: Vec::new(),
            input: unspent.txins,
            output: outputs,
            join_split_sig: None,
            join_split_pubkey: None,
            binding_sig: None,

        };
        let mut input_amounts = unspent.amounts_sat;
        input_amounts.reverse();
        let secp = secp256k1::Secp256k1::new();
        for input_index in 0..transaction.input.len() {
            let cur_amount = input_amounts.pop().unwrap();
            let sig_hash = transaction.signature_hash(input_index, script, 0x01, 0x00, cur_amount);
            let msg = secp256k1::Message::from_slice(sig_hash.as_bytes()).unwrap();
            let sk = secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap();
            let pub_key = secp256k1::key::PublicKey::from_secret_key(&secp, &sk);
            let mut sig_vec = secp.sign(&msg, &sk).serialize_der(&secp);
            sig_vec.push(0x01);
            let mut script_sig = bitcoin_zcash::blockdata::script::Builder::new()
               .push_slice(&sig_vec)
               .push_slice(&pub_key.serialize())
               .push_opcode(OP_FALSE_ZEC)
               .push_slice(&mut script.to_bytes())
               .into_script();
            transaction.input[input_index].script_sig = script_sig.clone();
        }
        Ok(transaction)
    }

    fn in_stages_fulfiller<F, T>(&self, f_fulfiller: F) -> TradeResult<T> where
        F: FnOnce(&ContractParams) -> TradeResult<T> {
        match self.contract {
            Contract::Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::Undef(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Init(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::InitiatorFunded(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Funded(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::InitiatorRedeemed(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Complete(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Refunded(ref params) => f_fulfiller(params),
                }
            },
            _ => {Err(TradeError::Default)}
        }
    }

    fn get_params(&self) -> ContractParams {
        let mut result: Option<ContractParams> = None;
        match self.in_stages_initiator::<_, ()>(|params| {
            result = Some(params.clone());
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        match self.in_stages_fulfiller::<_, ()>(|params| {
            result = Some(params.clone());
            Ok(())
        }) {
            Ok(_) => {},
            Err(_) => {}
        };
        result.unwrap()
    }

    fn change_params<F>(&self, f: F) -> Self
    where
        F: FnOnce(&ContractParams) -> ContractParams {
        use  self::Contract::{*};
        let contract = match self.contract {
            Initiator(ref stage) => {
                use self::ContractStageInitiator::{*};
                match stage {
                    Undef(ref params) => Initiator(Undef(f(params))),
                    Init(ref params) => Initiator(Init(f(params))),
                    Funded(ref params) => Initiator(Funded(f(params))),
                    FulfillerFunded(ref params) => Initiator(FulfillerFunded(f(params))),
                    Complete(ref params) => Initiator(Complete(f(params))),
                    Refunded(ref params) => Initiator(Refunded(f(params))),
                }
            },
            Fulfiller(ref stage) => {
                use self::ContractStageFulfiller::{*};
                match stage {
                    Undef(ref params) => Fulfiller(Undef(f(params))),
                    Init(ref params) => Fulfiller(Init(f(params))),
                    InitiatorFunded(ref params) => Fulfiller(InitiatorFunded(f(params))),
                    Funded(ref params) => Fulfiller(Funded(f(params))),
                    InitiatorRedeemed(ref params) => Fulfiller(InitiatorRedeemed(f(params))),
                    Complete(ref params) => Fulfiller(Complete(f(params))),
                    Refunded(ref params) => Fulfiller(Refunded(f(params))),
                }
            },
        };
        Trade {
            version: TRADE_VERSION,
            id: self.id.clone(),
            contract: contract
        }
    }

    fn change_stage(&self, stage: Stage) -> Self {
        use  self::Contract::{*};
        use  self::Stage::{*};
        let contract = match self.contract {
            Initiator(_) => {
                use  self::ContractStageInitiator::{*};
                match stage {
                    InitiatorUndef => Initiator(Undef(self.get_params())),
                    InitiatorInit => Initiator(Init(self.get_params())),
                    InitiatorFunded => Initiator(Funded(self.get_params())),
                    InitiatorFulfillerFunded => Initiator(FulfillerFunded(self.get_params())),
                    InitiatorComplete => Initiator(Complete(self.get_params())),
                    InitiatorRefunded => Initiator(Undef(self.get_params())),
                    _ => unreachable!()
                }
            },
            Fulfiller(_) => {
                use  self::ContractStageFulfiller::{*};
                match stage {
                    FulfillerUndef => Fulfiller(Undef(self.get_params())),
                    FulfillerInit => Fulfiller(Init(self.get_params())),
                    FulfillerInitiatorFunded => Fulfiller(InitiatorFunded(self.get_params())),
                    FulfillerFunded => Fulfiller(Funded(self.get_params())),
                    FulfillerInitiatorRedeemed => Fulfiller(InitiatorRedeemed(self.get_params())),
                    FulfillerComplete => Fulfiller(Complete(self.get_params())),
                    FulfillerRefunded => Fulfiller(Refunded(self.get_params())),
                    _ => unreachable!()
                }
            }
        };
        Trade {
            version: TRADE_VERSION,
            id: self.id.clone(),
            contract: contract
        }
    }

    fn change_role_and_reset(&self, role: Role) -> Self {
        let contract = match role {
            Role::Initiator => Contract::Initiator(ContractStageInitiator::Undef(self.get_params())),
            Role::Fulfiller => Contract::Fulfiller(ContractStageFulfiller::Undef(self.get_params()))
        };
        Trade {
            version: TRADE_VERSION,
            id: self.id.clone(),
            contract: contract
        }
    }
    #[allow(dead_code)]
    fn in_stages<F, T>(&self, f_initiator: F, f_fulfiller: F) -> TradeResult<T> where
        F: FnOnce(&ContractParams) -> TradeResult<T> {
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Undef(ref params) => f_initiator(params),
                    ContractStageInitiator::Init(ref params) => f_initiator(params),
                    ContractStageInitiator::Funded(ref params) => f_initiator(params),
                    ContractStageInitiator::FulfillerFunded(ref params) => f_initiator(params),
                    ContractStageInitiator::Complete(ref params) => f_initiator(params),
                    ContractStageInitiator::Refunded(ref params) => f_initiator(params),
                }
            },
            Contract::Fulfiller(ref stage) => {
                match stage {
                    ContractStageFulfiller::Undef(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Init(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::InitiatorFunded(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Funded(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::InitiatorRedeemed(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Complete(ref params) => f_fulfiller(params),
                    ContractStageFulfiller::Refunded(ref params) => f_fulfiller(params),
                }
            }
        }
    }


    fn in_stages_initiator<F, T>(&self, f_initiator: F) -> TradeResult<T> where
        F: FnOnce(&ContractParams) -> TradeResult<T> {
        match self.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    ContractStageInitiator::Undef(ref params) => f_initiator(params),
                    ContractStageInitiator::Init(ref params) => f_initiator(params),
                    ContractStageInitiator::Funded(ref params) => f_initiator(params),
                    ContractStageInitiator::FulfillerFunded(ref params) => f_initiator(params),
                    ContractStageInitiator::Complete(ref params) => f_initiator(params),
                    ContractStageInitiator::Refunded(ref params) => f_initiator(params),
                }
            },
            _ => {Err(TradeError::Default)}
        }
    }

    #[allow(dead_code)]
    fn clone_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Clone,
    {
        let mut a = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
        a
    }

    /// Waiting for the Initiator to send money to contract script.
    fn check_initiator_funded(params: & ContractParams,
            is_initiator: bool,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Contract> {
        use swas::ExchangeData::{Btc, Zec};
        use swas::Contract::{Initiator, Fulfiller};
        let funded;
        match params.exchange_data_coin_sell {
            Btc(ref exdata) => {
                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                funded = match rpc_btc.getreceivedbyaddress(&addr, min_confirmations) {
                    Ok(funds) => funds,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.getreceivedbyaddress({}, {})", addr, min_confirmations).into(),
                        rpc_err: e
                    })
                };
            },
            Zec(ref exdata) => {
                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                funded = match rpc_zec.getreceivedbyaddress(&addr, min_confirmations) {
                    Ok(funds) => funds,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.getreceivedbyaddress({}, {})", addr, min_confirmations).into(),
                        rpc_err: e
                    })
                };
            },
        };
        if funded > 0.0 {
            if is_initiator == true {
                Ok(Initiator(ContractStageInitiator::Funded(params.clone())))
            } else {
                Ok(Fulfiller(ContractStageFulfiller::InitiatorFunded(params.clone())))
            }
        }else {
            if is_initiator == true {
                Ok(Initiator(ContractStageInitiator::Init(params.clone())))
            } else {
                Ok(Fulfiller(ContractStageFulfiller::Init(params.clone())))
            }
        }
    }

    /// Waiting for the Fulfiller to send money to contract script (opposite blockchain).
    fn check_fulfiller_funded(params: & ContractParams,
            is_initiator: bool,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Contract> {
        use swas::ExchangeData::{Btc, Zec};
        use swas::Contract::{Initiator, Fulfiller};
        use swas::ContractStageInitiator::{FulfillerFunded};
        let funded;
        match params.exchange_data_coin_buy {
            Btc(ref exdata) => {
                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                funded = match rpc_btc.getreceivedbyaddress(&addr, min_confirmations) {
                    Ok(funds) => funds,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.getreceivedbyaddress({}, {})", addr, min_confirmations).into(),
                        rpc_err: e
                    })
                };
            },
            Zec(ref exdata) => {
                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                funded = match rpc_zec.getreceivedbyaddress(&addr, min_confirmations) {
                    Ok(funds) => funds,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.getreceivedbyaddress({}, {})", addr, min_confirmations).into(),
                        rpc_err: e
                    })
                };
            },
        };
        if funded > 0.0 {
            if is_initiator == true {
                Ok(Initiator(FulfillerFunded(params.clone())))
            } else {
                Ok(Fulfiller(ContractStageFulfiller::Funded(params.clone())))
            }
        } else {
            Self::check_initiator_funded(&params, is_initiator, min_confirmations, rpc_btc, rpc_zec)
        }
    }

    fn get_received_from_p2sh_btc(script: &[u8],
            addr: String,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<f64> {
    use self::bitcoin::blockdata::script::Builder;

        let mut amount_received: f64 = 0.0;
        let received_by_address = match rpc_btc.listreceivedbyaddress(min_confirmations, false, true) {
            Ok(received) => received,
            Err(e) => return Err(TradeError::RpcError{
                call: format!("rpc_btc.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                rpc_err: e
            })
        };
        for received in received_by_address {
            if received.address == addr {
                for txid in received.txids {
                    let tx_raw = match rpc_btc.getrawtransaction_verbose(txid.as_ref()) {
                        Ok(tx_raw) => tx_raw,
                        Err(e) =>  match e {
                            exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                            _ => return Err(TradeError::RpcError{
                                call: format!("rpc_btc.getrawtransaction_verbose({}), addr= {}", txid, addr).into(),
                                rpc_err: e
                            })
                        }
                    };
                    for (i, vout) in tx_raw.vout.iter().enumerate() {
                        match &vout.script_pubkey.addresses {
                            Some(addresses) => {
                                if addresses.len() != 1 {
                                    return Err(TradeError::Other("Ooops... Something wrong (0)".into()))
                                } else {
                                    if addresses.clone().pop().unwrap() == addr {
                                        let witness_data_string = tx_raw.vin[i].txinwitness.clone();
                                        if witness_data_string == None {
                                            continue;
                                        }
                                        let mut witness_data : Vec<Vec<u8>> = Vec::new();
                                        for witness_data_slice in witness_data_string.unwrap() {
                                            witness_data.push(witness_data_slice.from_hex().unwrap());
                                        }

                                        if witness_data.len() != 5 {
                                            continue;
                                        }
                                        let truescript = Builder::new().push_opcode(OP_TRUE).into_script().as_bytes().to_vec();
                                        if witness_data[4].as_slice() == script && witness_data[3] == truescript {
                                            amount_received+= vout.value;
                                        }
                                    }
                                }
                            },
                            None => return Err(TradeError::Other("Ooops... Something wrong (1)".into()))
                        }
                    }
                }
            }
        }
        Ok(amount_received)
    }

    fn get_received_from_p2sh_zec(script: &[u8],
            addr: String,
            min_confirmations: u64,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<f64> {
        use swas::bitcoin_zcash::blockdata::script::Instruction::{*};
        let mut amount_received: f64 = 0.0;
        let received_by_address = match rpc_zec.listreceivedbyaddress(min_confirmations, false, true) {
            Ok(answer) => answer,
            Err(e) => return Err(TradeError::RpcError{
                call: format!("rpc_zec.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                rpc_err: e
            })
        };
        for received in received_by_address {
            if received.address == addr {
                for txid in received.txids {
                    let tx_raw = match rpc_zec.getrawtransaction_verbose_zec(txid.as_ref()) {
                        Ok(tx_raw) => tx_raw,
                        Err(e) => match e {
                            exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                            _ => return Err(TradeError::RpcError{
                                call: format!("rpc_zec.getrawtransaction_verbose_zec({}), addr= {}", txid, addr).into(),
                                rpc_err: e
                            })
                        }
                    };
                    for (i, vout) in tx_raw.vout.iter().enumerate() {
                        match &vout.script_pubkey.addresses {
                            Some(addresses) => {
                                if addresses.len() != 1 {
                                    return Err(TradeError::Other("Ooops... Something wrong (0)".into()))
                                }else {
                                    if addresses.clone().pop().unwrap() == addr {
                                        let script_sig = bitcoin_zcash::blockdata::script::Script::from(tx_raw.vin[i].script_sig.hex.from_hex().unwrap());
                                        let mut redeem_flag = false;
                                        for (k, instruction) in script_sig.into_iter().enumerate() {
                                            match instruction {
                                                PushBytes(bytes) => {
                                                    if k == 4 && redeem_flag == true {
                                                        if bytes == script {
                                                            amount_received+= vout.value;
                                                        }
                                                    }
                                                },
                                                Op(opcode) => {
                                                    if k == 3 && opcode == OP_TRUE_ZEC {
                                                        redeem_flag = true;
                                                    }
                                                },
                                                Error(error) => {
                                                    return Err(TradeError::Other(format!("script_sig error: pos={}, error: {:?}", k, error)));
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            None => return Err(TradeError::Other("Ooops... Something wrong (1)".into()))
                        }
                    }
                }
            }
        }
        Ok(amount_received)
    }

    fn save_secret_from_redeem_tx(params: &mut ContractParams,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<()> {
        use swas::ExchangeData::{Btc, Zec};
        use self::bitcoin::blockdata::script::Builder;
        match params.exchange_data_coin_buy {
            Btc(ref exdata) => {
                let received_by_address = match rpc_btc.listreceivedbyaddress(min_confirmations, false, true) {
                    Ok(received) => received,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                        rpc_err: e
                    })
                };
                let addr = format!("{}", exdata.wallets.initiator);
                for received in received_by_address {
                    if received.address == addr {
                        for txid in received.txids {
                            let tx_raw = match rpc_btc.getrawtransaction_verbose(txid.as_ref()) {
                                Ok(tx_raw) => tx_raw,
                                Err(e) =>  match e {
                                    exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                    _ => return Err(TradeError::RpcError{
                                        call: format!("rpc_btc.getrawtransaction_verbose({})", txid).into(),
                                        rpc_err: e
                                    })
                                }
                            };
                            for (i, vout) in tx_raw.vout.iter().enumerate() {
                                match &vout.script_pubkey.addresses {
                                    Some(addresses) => {
                                        if addresses.len() != 1 {
                                            return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)));
                                        }else {
                                            if addresses.clone().pop().unwrap() == addr {

                                                let mut suspected_bytes: Option<Vec<u8>> = None;

                                                let witness_data_string = tx_raw.vin[i].txinwitness.clone();
                                                if witness_data_string == None {
                                                    continue;
                                                }
                                                let mut witness_data : Vec<Vec<u8>> = Vec::new();
                                                for witness_data_slice in witness_data_string.unwrap() {
                                                    witness_data.push(witness_data_slice.from_hex().unwrap());
                                                }

                                                if witness_data.len() == 5 {
                                                    let truescript = Builder::new().push_opcode(OP_TRUE).into_script().as_bytes().to_vec();
                                                    if witness_data[4].as_slice() == exdata.script.as_bytes() && witness_data[3] == truescript {
                                                        suspected_bytes = Some(witness_data[2].clone());
                                                    }
                                                    match suspected_bytes {
                                                        Some(bytes) => {
                                                            params.secret = Some(bytes);
                                                        },
                                                        None => {}
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                }
                            }
                        }
                    }
                }
            }
            Zec(ref exdata) => {
                use swas::bitcoin_zcash::blockdata::script::Instruction::{*};
                let received_by_address = match rpc_zec.listreceivedbyaddress(min_confirmations, false, true) {
                    Ok(received) => received,
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                        rpc_err: e
                    })
                };
                let addr = format!("{}", exdata.wallets.initiator);
                for received in received_by_address {
                    if received.address == addr {
                        for txid in received.txids {
                            let tx_raw = match rpc_zec.getrawtransaction_verbose_zec(txid.as_ref()) {
                                Ok(tx_raw) => tx_raw,
                                Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_zec.getrawtransaction_verbose_zec({}), addr: {}", txid, addr).into(),
                                            rpc_err: e
                                        })
                                }
                            };
                            for (i, vout) in tx_raw.vout.iter().enumerate() {
                                match &vout.script_pubkey.addresses {
                                    Some(addresses) => {
                                        if addresses.len() != 1 {
                                            return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                        }else {
                                            if addresses.clone().pop().unwrap() == addr {
                                                let script_sig = bitcoin_zcash::blockdata::script::Script::from(tx_raw.vin[i].script_sig.hex.from_hex().unwrap());
                                                let mut redeem_flag = false;
                                                let mut transaction_check_flag = false;
                                                let mut suspected_bytes: Option<Vec<u8>> = None;
                                                for (k, instruction) in script_sig.into_iter().enumerate() {
                                                    match instruction {
                                                        PushBytes(bytes) => {
                                                            if k == 2 {
                                                                suspected_bytes = Some(bytes.to_vec());
                                                            }
                                                            if k == 4 && redeem_flag == true {
                                                                if bytes == exdata.script.as_bytes() {
                                                                    transaction_check_flag = true;
                                                                }
                                                            }
                                                        },
                                                        Op(opcode) => {
                                                            if k == 3 && opcode == OP_TRUE_ZEC {
                                                                redeem_flag = true;
                                                            }
                                                        },
                                                        Error(error) => {
                                                            return Err(TradeError::Other(format!("script_sig error: pos={}, error: {:?}", k, error)))
                                                        }
                                                    }
                                                }
                                                match suspected_bytes {
                                                    Some(bytes) => {
                                                        if transaction_check_flag == true {
                                                            params.secret = Some(bytes);
                                                        }
                                                    },
                                                    None => {}
                                                }
                                            }
                                        }
                                    },
                                    None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                }
                            }
                        }
                    }
                }
            }
        }
        match &params.secret {
            Some(_) => {Ok(())},
            None => {
                Err(TradeError::Other("Invalid initiator's redeem transaction".into()))
            }
        }
    }

    fn check_initiator_redeemed(params: ContractParams,
            is_initiator: bool,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Contract> {
        use swas::ExchangeData::{Btc, Zec};
        use swas::Contract::{Initiator, Fulfiller};
        use swas::ContractStageInitiator::{FulfillerFunded, Complete};
        use swas::ContractStageFulfiller::{InitiatorRedeemed};
        let amount_received: f64;
        let addr: String;
        match params.exchange_data_coin_buy {
            Btc(ref exdata) => {
                addr = format!("{}", exdata.wallets.initiator);
                if is_initiator == true {
                    let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.initiator.network).to_string());
                    match rpc_btc.listunspent(min_confirmations as u32, 9999999, &[&script_addr]) {
                        Ok(listunspent) => {
                            if listunspent.len() > 0 {
                                return Ok(Initiator(FulfillerFunded(params.clone())))
                            }
                        },
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_btc.listunspent({}, {})", min_confirmations, script_addr).into(),
                            rpc_err: e
                        })
                    }
                }
                amount_received = Self::get_received_from_p2sh_btc(exdata.script.as_bytes(), addr, min_confirmations, rpc_btc)?;
            },
            Zec(ref exdata) => {
                addr = format!("{}", exdata.wallets.initiator);
                if is_initiator == true {
                    let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.initiator.network).to_string());
                    match rpc_zec.listunspent(min_confirmations as u32, 9999999, &[&script_addr]) {
                        Ok(listunspent) => {
                            if listunspent.len() > 0 {
                                return Ok(Initiator(FulfillerFunded(params.clone())))
                            }
                        },
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_zec.listunspent({}, {})", min_confirmations, script_addr).into(),
                            rpc_err: e
                        })
                    }
                }
                amount_received = Self::get_received_from_p2sh_zec(exdata.script.as_bytes(), addr, min_confirmations, rpc_zec)?;
            },
        };
        if amount_received > 0.0 {
            if is_initiator == true {
                Ok(Initiator(Complete(params)))
            } else {
                let mut new_params = params.clone();
                Self::save_secret_from_redeem_tx(&mut new_params, min_confirmations, rpc_btc, rpc_zec)?;
                Ok(Fulfiller(InitiatorRedeemed(new_params)))
            }
        }else {
            Self::check_fulfiller_funded(&params, is_initiator, min_confirmations, rpc_btc, rpc_zec)
        }
    }

    fn check_refunded(params: & ContractParams,
            check_initiator: bool,
            is_filfiller_funded: bool,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Contract> {
        use swas::ExchangeData::{Btc, Zec};
        use swas::Contract::{Initiator, Fulfiller};
        let mut amount_refunded: f64 = 0.0;
        if check_initiator == false {
            match params.exchange_data_coin_buy {
                Btc(ref exdata) => {
                    let received_by_address = match rpc_btc.listreceivedbyaddress(min_confirmations, false, true) {
                        Ok(received) => received,
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_btc.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                            rpc_err: e
                        })
                    };
                    let addr = format!("{}", exdata.wallets.fulfiller);
                    for received in received_by_address {
                        if received.address == addr {
                            for txid in received.txids {
                                let tx_raw = match rpc_btc.getrawtransaction_verbose(txid.as_ref()) {
                                    Ok(tx_raw) => tx_raw,
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_btc.getrawtransaction_verbose({})", txid).into(),
                                            rpc_err: e
                                        })
                                    }
                                };
                                for (i, vout) in tx_raw.vout.iter().enumerate() {
                                    match &vout.script_pubkey.addresses {
                                        Some(addresses) => {
                                            if addresses.len() != 1 {
                                                return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                            } else {
                                                if addresses.clone().pop().unwrap() == addr {
                                                    let witness_data_string = tx_raw.vin[i].txinwitness.clone();
                                                    if witness_data_string == None {
                                                        continue;
                                                    }

                                                    let mut witness_data : Vec<Vec<u8>> = Vec::new();
                                                    for witness_data_slice in witness_data_string.unwrap() {
                                                        witness_data.push(witness_data_slice.from_hex().unwrap());
                                                    }

                                                    if witness_data.len() != 4 {
                                                        continue;
                                                    }
                                                    if witness_data[3].as_slice() == exdata.script.as_bytes() && witness_data[2].len() == 0 {
                                                        amount_refunded+= vout.value;
                                                    }
                                                }
                                            }
                                        },
                                        None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                    }
                                }
                            }
                        }
                    }
                },
                Zec(ref exdata) => {
                    use swas::bitcoin_zcash::blockdata::script::Instruction::{*};
                    let mut received_by_address = match rpc_zec.listreceivedbyaddress(min_confirmations, false, true) {
                        Ok(answer) => answer,
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_zec.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                            rpc_err: e
                        })
                    };
                    let addr = format!("{}", exdata.wallets.fulfiller);
                    for received in received_by_address {
                        if received.address == addr {
                            for txid in received.txids {
                                let tx_raw = match rpc_zec.getrawtransaction_verbose_zec(txid.as_ref()) {
                                    Ok(tx_raw) => tx_raw,
                                    Err(e) => match e {
                                        exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                        _ => return Err(TradeError::RpcError{
                                                call: format!("rpc_zec.getrawtransaction_verbose_zec({}), addr: {}", txid, addr).into(),
                                                rpc_err: e
                                            })
                                        }
                                };
                                for (i, vout) in tx_raw.vout.iter().enumerate() {
                                    match &vout.script_pubkey.addresses {
                                        Some(addresses) => {
                                            if addresses.len() != 1 {
                                                return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                            }else {
                                                if addresses.clone().pop().unwrap() == addr {
                                                    let script_sig = bitcoin_zcash::blockdata::script::Script::from(tx_raw.vin[i].script_sig.hex.from_hex().unwrap());
                                                    let mut refund_flag = false;
                                                    for (k, instruction) in script_sig.into_iter().enumerate() {
                                                        match instruction {
                                                            PushBytes(bytes) => {
                                                                if k == 2 && bytes.len() == 0 {
                                                                    refund_flag = true;
                                                                }
                                                                if k == 3 && refund_flag == true {
                                                                    if bytes == exdata.script.as_bytes() {
                                                                        amount_refunded+= vout.value;
                                                                    }
                                                                }
                                                            },
                                                            Op(_) => {},
                                                            Error(error) => {
                                                                return Err(TradeError::Other(format!("script_sig error: pos={}, error: {:?}", k, error)))
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                    }
                                }
                            }
                        }
                    }
                },
            };
        } else {
            match params.exchange_data_coin_sell {
                Btc(ref exdata) => {
                    let received_by_address = match rpc_btc.listreceivedbyaddress(min_confirmations, false, true) {
                        Ok(received) => received,
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_btc.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                            rpc_err: e
                        })
                    };
                    let addr = format!("{}", exdata.wallets.initiator);
                    for received in received_by_address {
                        if received.address == addr {
                            for txid in received.txids {
                                let tx_raw = match rpc_btc.getrawtransaction_verbose(txid.as_ref()) {
                                    Ok(tx_raw) => tx_raw,
                                    Err(e) =>  match e {
                                        exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                        _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_btc.getrawtransaction_verbose({})", txid).into(),
                                            rpc_err: e
                                        })
                                    }
                                };
                                for (i, vout) in tx_raw.vout.iter().enumerate() {
                                    match &vout.script_pubkey.addresses {
                                        Some(addresses) => {
                                            if addresses.len() != 1 {
                                                return Err(TradeError::Other("Ooops... Something wrong (0)".into()))
                                            } else {
                                                if addresses.clone().pop().unwrap() == addr {
                                                    let witness_data_string = tx_raw.vin[i].txinwitness.clone();
                                                    if witness_data_string == None {
                                                        continue;
                                                    }

                                                    let mut witness_data : Vec<Vec<u8>> = Vec::new();
                                                    for witness_data_slice in witness_data_string.unwrap() {
                                                        witness_data.push(witness_data_slice.from_hex().unwrap());
                                                    }

                                                    if witness_data.len() != 4 {
                                                        continue;
                                                    }
                                                    if witness_data[3].as_slice() == exdata.script.as_bytes() && witness_data[2].len() == 0 {
                                                        amount_refunded+= vout.value;
                                                    }
                                                }
                                            }
                                        },
                                        None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                    }
                                }
                            }
                        }
                    }
                },
                Zec(ref exdata) => {
                    use swas::bitcoin_zcash::blockdata::script::Instruction::{*};
                    let mut received_by_address = match rpc_zec.listreceivedbyaddress(min_confirmations, false, true) {
                        Ok(answer) => answer,
                        Err(e) => return Err(TradeError::RpcError{
                            call: format!("rpc_zec.listreceivedbyaddress({}, false, true)", min_confirmations).into(),
                            rpc_err: e
                        })
                    };
                    let addr = format!("{}", exdata.wallets.initiator);
                    for received in received_by_address {
                        if received.address == addr {
                            for txid in received.txids {
                                let tx_raw = match rpc_zec.getrawtransaction_verbose_zec(txid.as_ref()) {
                                    Ok(tx_raw) => tx_raw,
                                    Err(e) => match e {
                                            exonum_bitcoinrpc_zec_exp::Error::NoInformation(_) => continue,
                                            _ => return Err(TradeError::RpcError{
                                            call: format!("rpc_zec.getrawtransaction_verbose_zec({})", txid).into(),
                                            rpc_err: e
                                        })
                                    }
                                };
                                for (i, vout) in tx_raw.vout.iter().enumerate() {
                                    match &vout.script_pubkey.addresses {
                                        Some(addresses) => {
                                            if addresses.len() != 1 {
                                                return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                            }else {
                                                if addresses.clone().pop().unwrap() == addr {
                                                    let script_sig = bitcoin_zcash::blockdata::script::Script::from(tx_raw.vin[i].script_sig.hex.from_hex().unwrap());
                                                    let mut refund_flag = false;
                                                    for (k, instruction) in script_sig.into_iter().enumerate() {
                                                        match instruction {
                                                            PushBytes(bytes) => {
                                                                if k == 2 && bytes.len() == 0 {
                                                                    refund_flag = true;
                                                                }
                                                                if k == 3 && refund_flag == true {
                                                                    if bytes == exdata.script.as_bytes() {
                                                                        amount_refunded+= vout.value;
                                                                    }
                                                                }
                                                            },
                                                            Op(_) => {},
                                                            Error(error) => {
                                                                return Err(TradeError::Other(format!("script_sig error: pos={}, error: {:?}", k, error)))
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        None => return Err(TradeError::Other(format!("{:?} transaction not supported", tx_raw)))
                                    }
                                }
                            }
                        }
                    }
                },
            };
        }
        if amount_refunded > 0.0 {
            if check_initiator == true {
                Ok(Initiator(ContractStageInitiator::Refunded(params.clone())))
            } else {
                Ok(Fulfiller(ContractStageFulfiller::Refunded(params.clone())))
            }
        }else {
            if check_initiator == true {
                if is_filfiller_funded == true {
                    Self::check_fulfiller_funded(params, true, min_confirmations, rpc_btc, rpc_zec)
                } else {
                    Ok(Initiator(ContractStageInitiator::Funded(params.clone())))
                }
            } else {
                Ok(Fulfiller(ContractStageFulfiller::Funded(params.clone())))
            }
        }
    }

    /// Copy without seret
    pub fn without_secret(&self) -> Trade {
        self.change_params(
            |params| {
                let mut new_params = params.clone();
                new_params.secret = None;
                new_params
            }
        )
    }

    fn check_fulfiller_redeemed(params: ContractParams,
            min_confirmations: u64,
            rpc_btc : & exonum_bitcoinrpc_zec_exp::Client,
            rpc_zec : & exonum_bitcoinrpc_zec_exp::Client) -> TradeResult<Contract> {
    use swas::ExchangeData::{Btc, Zec};
    use swas::Contract::Fulfiller;
    use swas::ContractStageFulfiller::{*};
        let amount_received: f64;
        match params.exchange_data_coin_sell {
            Btc(ref exdata) => {
                let script_addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.initiator.network).to_string());
                match rpc_btc.listunspent(min_confirmations as u32, 9999999, &[&script_addr]) {
                    Ok(listunspent) => {
                        if listunspent.len() > 0 {
                            return Ok(Fulfiller(InitiatorRedeemed(params.clone())))
                        }
                    },
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_btc.listunspent({}, {})", min_confirmations, script_addr).into(),
                        rpc_err: e
                    })
                }
                amount_received = Self::get_received_from_p2sh_btc(exdata.script.as_bytes(),
                        format!("{}", exdata.wallets.fulfiller), min_confirmations, rpc_btc)?;
            },
            Zec(ref exdata) => {
                let script_addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.initiator.network).to_string());
                match rpc_zec.listunspent(min_confirmations as u32, 9999999, &[&script_addr]) {
                    Ok(listunspent) => {
                        if listunspent.len() > 0 {
                            return Ok(Fulfiller(InitiatorRedeemed(params.clone())))
                        }
                    },
                    Err(e) => return Err(TradeError::RpcError{
                        call: format!("rpc_zec.listunspent({}, {})", min_confirmations, script_addr).into(),
                        rpc_err: e
                    })
                }
                amount_received = Self::get_received_from_p2sh_zec(exdata.script.as_bytes(),
                        format!("{}", exdata.wallets.fulfiller), min_confirmations, rpc_zec)?;
            },
        };
        if amount_received > 0.0 {
                Ok(Fulfiller(Complete(params.clone())))
        }else {
                Self::check_initiator_redeemed(params, false, min_confirmations, rpc_btc, rpc_zec)
        }
    }

    /// Get trade version
    pub fn get_version(&self) -> u16 {
        self.version
    }
}

//#[cfg(test)]
mod tests {
    extern crate bitcoin;
    extern crate bitcoin_zcash;
    extern crate serde;
    extern crate serde_json;
    extern crate secp256k1;
    extern crate rustc_serialize;
    extern crate crypto;
    use std::str::{self, FromStr};
    use self::bitcoin::util::address::Address as BtcAddress;
    use self::bitcoin_zcash::util::address::Address as ZecAddress;
    #[allow(unused_imports)]
    use super::{Trade, Contract, ContractStageInitiator,
                exonum_bitcoinrpc_zec_exp::Client as RpcClient_, Currency,
                TradeBlank, TradeBlankParams, TradeBlankParameters, TradeBlankCurParams, TradeBlankParticipant,
                Stage::{*}, Role};

    const P2SH_FEE : f64 = 0.0005;
    const MINCONF : u64 = 0;
    const AMOUNT_ZEC : f64 = 0.02;
    const AMOUNT_BTC : f64 = 0.01;

    #[allow(dead_code)]
    fn get_rpcs() -> (RpcClient_, RpcClient_) {
        let rpc_btc  = RpcClient_::new("http://127.0.0.1:18332/", Some("intectest".into()), Some("2PLD4jvuy6Mgoy0QIf9BNafpFtkXN2bJCfh7b9pHwlQ=".into()));
        let rpc_zec  = RpcClient_::new("http://127.0.0.1:18232/", Some("intectest".into()), Some("2PLD4jvuy6Mgoy0QIf9BNafpFtkXN2bJCfh7b9pHwlQ=".into()));
        (rpc_btc, rpc_zec)
    }

    #[allow(dead_code)]
    fn get_tradeblank(curr_buy: Currency, locktime_buy: u64, locktime_sell: u64, rpc_btc: &RpcClient_, rpc_zec: &RpcClient_) -> TradeBlank {
        let current_blockcount_btc = match rpc_btc.getblockcount() {
            Ok(blockcount) => blockcount,
            Err(err) => panic!("rpc_btc.getblockcount(): {}", err)
        };
        let current_blockcount_zec = match rpc_zec.getblockcount() {
            Ok(blockcount) => blockcount,
            Err(err) => panic!("rpc_zec.getblockcount(): {}", err)
        };

        let mut blank: TradeBlank = TradeBlank::new("demo".into(), Role::Initiator, None, None, None);
        let trade_direction: TradeBlankParameters;
        let trade_id = "default".into();
        let secp = secp256k1::Secp256k1::new();

        let btcaddr_init = &get_new_addr_btc(rpc_btc, "swas-test");
        let btcaddr_init_priv_key = match rpc_btc.dumpprivkey(btcaddr_init) {
            Ok(key) => {
                let mut priv_key = bitcoin::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap()
            },
            Err(e) => panic!("rpc_btc.dumpprivkey: {}", e)
        };

        let zecaddr_init = &get_new_addr_zec(rpc_zec);
        let zecaddr_init_priv_key = match rpc_zec.dumpprivkey(zecaddr_init) {
            Ok(key) => {
                let mut priv_key = bitcoin_zcash::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap()
            },
            Err(e) => panic!("rpc_zec.dumpprivkey: {}", e)
        };

        blank.initiator.privkey_zec = Some(zecaddr_init_priv_key);
        blank.initiator.privkey_btc = Some(btcaddr_init_priv_key);
        blank.initiator.addr_zec = Some(bitcoin_zcash::util::address::Address::from_str(zecaddr_init).unwrap());
        blank.initiator.addr_btc = Some(bitcoin::util::address::Address::from_str(btcaddr_init).unwrap());


        let btcaddr_fulf = &get_new_addr_btc(rpc_btc, "swas-test");
        let btcaddr_fulf_priv_key = match rpc_btc.dumpprivkey(btcaddr_fulf) {
            Ok(key) => {
                let mut priv_key = bitcoin::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap()
            },
            Err(e) => panic!("rpc_btc.dumpprivkey: {}", e)
        };
        let zecaddr_fulf = &get_new_addr_zec(rpc_zec);
        let zecaddr_fulf_priv_key = match rpc_zec.dumpprivkey(zecaddr_fulf) {
            Ok(key) => {
                let mut priv_key = bitcoin_zcash::util::base58::from_check(&key).unwrap();
                priv_key.pop();
                priv_key.remove(0);
                secp256k1::key::SecretKey::from_slice(&secp, priv_key.as_slice()).unwrap()
            },
            Err(e) => panic!("rpc_zec.dumpprivkey: {}", e)
        };

        blank.fulfiller.privkey_btc = Some(btcaddr_fulf_priv_key);
        blank.fulfiller.privkey_zec = Some(zecaddr_fulf_priv_key);
        blank.fulfiller.addr_btc = Some(bitcoin::util::address::Address::from_str(btcaddr_fulf).unwrap());
        blank.fulfiller.addr_zec = Some(bitcoin_zcash::util::address::Address::from_str(zecaddr_fulf).unwrap());
        let btcparams = TradeBlankCurParams {
            amount: Some(AMOUNT_BTC),
            locktime: Some(current_blockcount_btc + match curr_buy {
                Currency::Bitcoin => locktime_buy,
                Currency::Zcash => locktime_sell,
            }),
            max_fee: Some(1000),
            confirmation_height: Some(MINCONF)
        };

        let zecparams = TradeBlankCurParams {
            amount: Some(AMOUNT_ZEC),
            locktime: Some(current_blockcount_zec + match curr_buy {
                Currency::Bitcoin => locktime_sell,
                Currency::Zcash => locktime_buy,
            }),
            max_fee: Some(1000),
            confirmation_height: Some(MINCONF)
        };

        match curr_buy {
            Currency::Bitcoin => {
                trade_direction = TradeBlankParameters::ZecToBtc(
                    TradeBlankParams {
                        buy: Some(btcparams),
                        sell: Some(zecparams)
                    }
                );
            },
            Currency::Zcash => {
                trade_direction = TradeBlankParameters::BtcToZec(
                    TradeBlankParams {
                        buy: Some(zecparams),
                        sell: Some(btcparams)
                    }
                );
            }
        }
        blank.id = trade_id;
        blank.params = Some(trade_direction);
        blank.secret = None;
        blank.secret_hash = None;
        println!("Tradeblank: {}", serde_json::to_string_pretty(&blank).unwrap());
        blank
    }

    #[allow(dead_code)]
    fn get_trade_zec_to_btc(
        rpc_btc: &RpcClient_,
        rpc_zec: &RpcClient_) -> Trade {
        get_tradeblank(Currency::Bitcoin, 50, 100, rpc_btc, rpc_zec).into_trade().unwrap()
    }

    fn get_new_addr_btc(rpc_btc: &RpcClient_, account: &str) -> String {
        let addr = match rpc_btc.getnewaddress(account) {
            Ok(answer) => answer,
            Err(e) => panic!("rpc_btc.getnewaddress(account): {}", e)
        };
        println!("new btc addr: {}", addr);
        addr
    }

    fn get_new_addr_zec(rpc_zec: &RpcClient_) -> String {
        let addr = match rpc_zec.getnewaddress("") {
            Ok(answer) => answer,
            Err(e) => panic!("rpc_zec.getnewaddres(\"\"): {}", e)
        };
        println!("new zec addr: {}", addr);
        addr
    }

    #[allow(dead_code)]
    fn get_trade_btc_to_zec(
        rpc_btc: &RpcClient_,
        rpc_zec: &RpcClient_) -> Trade {
        get_tradeblank(Currency::Zcash, 50, 100, rpc_btc, rpc_zec).into_trade().unwrap()
    }

    #[allow(dead_code)]
    fn get_trade_btc_to_zec_lcktm(
        rpc_btc: &RpcClient_,
        rpc_zec: &RpcClient_,
        locktime: u64) -> Trade {
        get_tradeblank(Currency::Zcash, locktime, locktime*2, rpc_btc, rpc_zec).into_trade().unwrap()
    }

    #[allow(dead_code)]
    fn get_trade_zec_to_btc_lcktm(
        rpc_btc: &RpcClient_,
        rpc_zec: &RpcClient_,
        locktime: u64) -> Trade {
        get_tradeblank(Currency::Bitcoin, locktime, locktime*2, rpc_btc, rpc_zec).into_trade().unwrap()
    }

    //    #[test]
    #[allow(dead_code)]
    fn check_payload()
    {
        let saddr: String = "2MsyrE6jWFF6fs6wMXbY3z7gVvPdHy4NTmb".into();
        let addr = BtcAddress::from_str(saddr.as_ref()).unwrap();
        println!("saddr = {}", saddr);
        println!("addr  = {}", addr.to_string());
        match addr.payload {
            bitcoin::util::address::Payload::ScriptHash(ref hash) => {
                println!("ScriptHash payload = {:02x?}", hash.as_bytes());
                assert_eq!("[08, 0f, b8, 74, 2c, 30, 01, 2a, 70, 33, 94, d5, 28, de, 8e, 21, 48, 4f, 02, d1]", format!("{:02x?}", hash.as_bytes()));
            },
            _ => {
                println!("unknown payload");
                panic!()
            }
        }
    }

    #[test]
    fn serde_trade() {
        let (rpc_btc, rpc_zec) = get_rpcs();
        let trade_btc_to_zec = get_trade_btc_to_zec(&rpc_btc, &rpc_zec);
        let serialized = serde_json::to_string_pretty(&trade_btc_to_zec).unwrap();
        let deserialized: Trade = serde_json::from_str(&serialized).unwrap();
        let serialized_again = serde_json::to_string_pretty(&deserialized).unwrap();
        assert_eq!(serialized, serialized_again);

        let trade_zec_to_btc = get_trade_zec_to_btc(&rpc_btc, &rpc_zec);
        let serialized = serde_json::to_string_pretty(&trade_zec_to_btc).unwrap();
        let deserialized: Trade = serde_json::from_str(&serialized).unwrap();
        let serialized_again = serde_json::to_string_pretty(&deserialized).unwrap();
        assert_eq!(serialized, serialized_again);
    }

    #[allow(dead_code)]
    fn pay_to_initiator_contract(trade: &Trade, rpc_btc: &RpcClient_, rpc_zec: &RpcClient_) -> Result<String, String> {
        use swas::ExchangeData::{Btc, Zec};
        match trade.contract {
            Contract::Initiator(ref stage) => {
                match stage {
                    // Initiator sent money to Contract script
                    // Waiting for the Fulfiller to send money to contract script.
                    ContractStageInitiator::Funded(ref params) => {
                        match params.exchange_data_coin_buy {
                            Btc(ref exdata) => {
                                // Send funds
                                let addr = format!("{}", BtcAddress::p2wsh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                match rpc_btc.sendtoaddress(&addr, (exdata.amount + P2SH_FEE).to_string().as_ref()) {
                                    Ok(txid) => Ok(txid),
                                    Err(e) => Err(format!("rpc_btc.sendtoaddress(&addr, ((exdata.amount)).to_string().as_ref()): {}", e))
                                }
                            },
                            Zec(ref exdata) => {
                                // Check if fulfiller redeemed
                                let addr = format!("{}", ZecAddress::p2sh(&exdata.script, exdata.wallets.fulfiller.network).to_string());
                                match rpc_zec.sendtoaddress(&addr, (exdata.amount + P2SH_FEE).to_string().as_ref()) {
                                    Ok(txid) => Ok(txid),
                                    Err(e) => Err(format!("rpc_zec.sendtoaddress(&addr, ((exdata.amount)).to_string().as_ref()): {}", e))
                                }
                            },
                        }
                    },
                    _ => Err("Undef state".into()),
                }
            },
            Contract::Fulfiller(ref _stage) => Err("Undef state".into()),
        }
    }

    #[test]
    fn trade_check_btc_to_zec_initiator() {
        let (rpc_btc, rpc_zec) = get_rpcs();
        let mut trade = get_trade_btc_to_zec(&rpc_btc, &rpc_zec);
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        let fulf_fund_txid = pay_to_initiator_contract(&trade, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn trade_check_initiator_zec_to_btc() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(1);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let mut trade = get_trade_zec_to_btc(&rpc_btc, &rpc_zec);
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        let fulf_fund_txid = pay_to_initiator_contract(&trade, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        sleep(sleep_time);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn trade_check_fulfiller_zec_to_btc() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(2);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let mut trade = get_trade_zec_to_btc(&rpc_btc, &rpc_zec);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        assert_eq!(trade.get_unredeemed_amount(MINCONF, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_BTC + 0.000_010);
        assert_eq!(trade_fulfiller.get_unredeemed_amount(MINCONF, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_ZEC + 0.000_010);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        sleep(sleep_time);
        match trade.refund(MINCONF, &rpc_btc, &rpc_zec) {
            Err(e) => match e {
                super::TradeError::RefundAttemptTooEarly{..} => panic!("Invalid redeem checking!"),
                super::TradeError::InvalidStage{..} => {},
                super::TradeError::Other(e) => panic!(e),
                _ => panic!("other")
            }
            Ok(_) => {
                panic!("Invalid redeem checking!");
            }
        }
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorRedeemed);
        let redeem_txid_fulfiller = trade_fulfiller.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid fulfiller: {}", redeem_txid_fulfiller);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn trade_check_fulfiller_btc_to_zec() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(1);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let mut trade = get_trade_btc_to_zec(&rpc_btc, &rpc_zec);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        assert_eq!(trade_fulfiller.get_unredeemed_amount(MINCONF, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_BTC + 0.000_010);
        assert_eq!(trade.get_unredeemed_amount(MINCONF, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_ZEC + 0.000_010);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        match trade.refund(MINCONF, &rpc_btc, &rpc_zec) {
            Err(e) => match e {
                super::TradeError::RefundAttemptTooEarly{..} => panic!("Invalid redeem checking!"),
                super::TradeError::InvalidStage{..} => {},
                super::TradeError::Other(e) => panic!(e),
                _ => panic!("other")
            }
            Ok(_) => {
                panic!("Invalid redeem checking!");
            }
        }
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorRedeemed);
        let redeem_txid_fulfiller = trade_fulfiller.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid fulfiller: {}", redeem_txid_fulfiller);
        sleep(sleep_time);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn trade_check_refund_fulfiller_btc_to_zec() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(5);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let locktime = 1;
        let mut trade = get_trade_btc_to_zec_lcktm(&rpc_btc, &rpc_zec, locktime);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        let start_blocknum_btc = rpc_btc.getblockcount().unwrap();
        let start_blocknum_zec = rpc_zec.getblockcount().unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        loop {
            match trade.refund(MINCONF, &rpc_btc, &rpc_zec) {
                Err(e) => match e {
                    super::TradeError::RefundAttemptTooEarly{
                        current_blocknum: c,
                        expected_blocknum: e
                    } => {
                        let current_blockcount_btc = rpc_btc.getblockcount().unwrap();
                        if current_blockcount_btc > (start_blocknum_btc + locktime*2) {
                            panic!("Invalid blockcount calculation!\nCurr: {}, Exp: {}. Actual curr: {} Actual exp: {}", c, e, current_blockcount_btc, (start_blocknum_btc + locktime*2))
                        } else {
                            println!("Wait: current_blockcount_btc = {}, (start_blocknum_btc + locktime) = {}",
                                current_blockcount_btc, (start_blocknum_btc + locktime*2));
                        }
                    },
                    super::TradeError::InvalidStage{..} => {},
                    super::TradeError::InvalidRole(_) => panic!("InvalidRole"),
                    super::TradeError::RpcError{call, rpc_err} => panic!("Rpc call failed: {} : {}", call, rpc_err),
                    super::TradeError::InvalidAmount(e) => panic!("{}", e),
                    super::TradeError::InvalidBtcAddress(e) => panic!("{}", e),
                    super::TradeError::InvalidZecAddress(e) => panic!("{}", e),
                    super::TradeError::NotSupportedBtcAddress(_) => panic!("NotSupportedBtcAddress"),
                    super::TradeError::InvalidBtcScriptSig(e) => panic!("{}", e),
                    super::TradeError::InvalidZecScriptSig(e) => panic!("{}", e),
                    super::TradeError::TooSmallBalance{..} => panic!("TooSmallBalance"),
                    super::TradeError::RefundAttemptTooEarly{..} => panic!("RefundAttemptTooEarly"),
                    super::TradeError::NothingToSpend(e) => panic!("{}", e),
                    super::TradeError::PrivKeyNotFound(e) => panic!("{}", e),
                    super::TradeError::InvalidImportString(e) => panic!("{}", e),
                    super::TradeError::Default => panic!("Default"),
                    super::TradeError::NetworkConsensusError(e) => panic!("{}", e),
                    super::TradeError::Other(e) => panic!("{}", e),
                    _ => panic!("otrer"),
                }
                Ok(txid) => {
                    let current_blockcount_btc = rpc_btc.getblockcount().unwrap();
                    if current_blockcount_btc < (start_blocknum_btc + locktime*2) {
                        panic!("current_blockcount_btc = {}, (start_blocknum_btc + locktime*2) = {}", current_blockcount_btc , (start_blocknum_btc + locktime*2))
                    } else {
                        println!("Refund txid intitiator (bitcoin): {:?}", match txid {
                            super::Txid::Btc(txid) => txid.be_hex_string(),
                            super::Txid::Zec(_) => panic!("invalid currency!")
                        });
                        break;
                    }

                }
            }
            sleep(sleep_time);
        }
        loop {
            match trade_fulfiller.refund(MINCONF, &rpc_btc, &rpc_zec) {
                Err(e) => match e {
                    super::TradeError::RefundAttemptTooEarly{..} => {
                        let current_blockcount_zec = rpc_zec.getblockcount().unwrap();
                        if current_blockcount_zec > (start_blocknum_zec + locktime) {
                            panic!("Invalid blockcount calculation!")
                        } else {
                            println!("Wait: start_blocknum_zec = {}, (start_blocknum_btc + locktime) = {}",
                                current_blockcount_zec, (start_blocknum_zec + locktime));
                        }
                    },
                    super::TradeError::InvalidStage{..} => {},
                    super::TradeError::Other(e) => panic!(e),
                    _ => panic!("other")
                }
                Ok(txid) => {
                    let current_blockcount_zec = rpc_zec.getblockcount().unwrap();
                    if current_blockcount_zec < (start_blocknum_zec + locktime) {
                        panic!("current_blockcount_zec = {}, (start_blocknum_zec + locktime) = {}", current_blockcount_zec , (start_blocknum_zec + locktime))
                    } else {
                        println!("Refund txid intitiator (zcash): {:?}", match txid {
                            super::Txid::Zec(txid) => txid.be_hex_string(),
                            super::Txid::Btc(_) => panic!("invalid currency!")
                        });
                        break;
                    }

                }
            }
            sleep(sleep_time);
        }
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorRefunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerRefunded);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorRefunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerRefunded);
    }

    #[test]
    fn trade_check_refund_zec_to_btc() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(5);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let locktime = 1;
        let mut trade = get_trade_zec_to_btc_lcktm(&rpc_btc, &rpc_zec, locktime);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        let start_blocknum_btc = rpc_btc.getblockcount().unwrap();
        let start_blocknum_zec = rpc_zec.getblockcount().unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        loop {
            match trade.refund(MINCONF, &rpc_btc, &rpc_zec) {
                Err(e) => match e {
                    super::TradeError::RefundAttemptTooEarly{..} => {
                        let current_blockcount_zec = rpc_zec.getblockcount().unwrap();
                        if current_blockcount_zec > (start_blocknum_zec + locktime*2) {
                            panic!("Invalid blockcount calculation!")
                        } else {
                            println!("Wait: current_blockcount_zec = {}, (start_blocknum_zec + locktime) = {}",
                                current_blockcount_zec, (start_blocknum_zec + locktime*2));
                        }
                    },
                    super::TradeError::AlreadyRedeemed => panic!("Not redeemed!"),
                    super::TradeError::Other(e) => panic!(e),
                    _ => panic!("other")
                }
                Ok(txid) => {
                    let current_blockcount_zec = rpc_zec.getblockcount().unwrap();
                    if current_blockcount_zec < (start_blocknum_zec + locktime*2) {
                        panic!("current_blockcount_zec = {}, (start_blocknum_zec + locktime*2) = {}", current_blockcount_zec , (start_blocknum_zec + locktime*2))
                    } else {
                        println!("Refund txid intitiator (zcash): {}", txid);
                        break;
                    }
                }
            }
            sleep(sleep_time);
        }
        loop {
            match trade_fulfiller.refund(MINCONF, &rpc_btc, &rpc_zec) {
                Err(e) => match e {
                    super::TradeError::RefundAttemptTooEarly{..} => {
                        let current_blockcount_btc = rpc_btc.getblockcount().unwrap();
                        if current_blockcount_btc > (start_blocknum_btc + locktime) {
                            panic!("Invalid blockcount calculation!")
                        } else {
                            println!("Wait: current_blockcount_btc = {}, (start_blocknum_btc + locktime) = {}",
                                current_blockcount_btc, (start_blocknum_btc + locktime));
                        }
                    },
                    super::TradeError::AlreadyRedeemed => panic!("Not redeemed!"),
                    super::TradeError::Other(e) => panic!(e),
                    _ => panic!("other")
                }
                Ok(txid) => {
                    let current_blockcount_btc = rpc_btc.getblockcount().unwrap();
                    if current_blockcount_btc < (start_blocknum_btc + locktime) {
                        panic!("current_blockcount_btc = {}, (start_blocknum_btc + locktime) = {}", current_blockcount_btc , (start_blocknum_btc + locktime))
                    } else {
                        println!("Refund txid fulfiller: {}", txid);
                        break;
                    }

                }
            }
            sleep(sleep_time);
        }
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorRefunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerRefunded);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorRefunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerRefunded);
    }

    #[test]
    fn trade_check_fulfiller_refund_zec_to_btc_initiator_redeemed() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(1);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let locktime = 1;
        let mut trade = get_trade_zec_to_btc_lcktm(&rpc_btc, &rpc_zec, locktime);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        match trade_fulfiller.refund(MINCONF, &rpc_btc, &rpc_zec) {
            Err(e) => match e {
                super::TradeError::RefundAttemptTooEarly{..} => panic!("Invalid redeem checking!"),
                super::TradeError::AlreadyRedeemed => {},
                super::TradeError::NothingToSpend(_) => {},
                super::TradeError::InvalidStage(_) => {},
                super::TradeError::Other(e) => panic!(e),
                _ => panic!("{}", e)
            }
            Ok(_) => {
                panic!("Invalid redeem checking!");
            }
        }
        sleep(sleep_time);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorRedeemed);
        let redeem_txid_fulfiller = trade_fulfiller.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid fulfiller: {}", redeem_txid_fulfiller);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn trade_check_fulfiller_refund_btc_to_zec_initiator_redeemed() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(1);
        let (rpc_btc, rpc_zec) = get_rpcs();
        let locktime = 1;
        let mut trade = get_trade_btc_to_zec_lcktm(&rpc_btc, &rpc_zec, locktime);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);
        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);
        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        let redeem_txid = trade.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        match trade_fulfiller.refund(MINCONF, &rpc_btc, &rpc_zec) {
            Err(e) => match e {
                super::TradeError::RefundAttemptTooEarly{..} => panic!("Invalid redeem checking!"),
                super::TradeError::AlreadyRedeemed => {},
                super::TradeError::NothingToSpend(_) => {},
                super::TradeError::InvalidStage(_) => {},
                super::TradeError::Other(e) => panic!(e),
                _ => panic!("{}", e)
            }
            Ok(_) => {
                panic!("Invalid redeem checking!");
            }
        }
        sleep(sleep_time);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorRedeemed);
        let redeem_txid_fulfiller = trade_fulfiller.redeem(1000, MINCONF, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid fulfiller: {}", redeem_txid_fulfiller);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn tradetime_check_fulfiller_btc_to_zec() {
        use std::{thread::sleep, time};
        let sleep_time = time::Duration::from_secs(1);
        let minconf = 1;
        let (rpc_btc, rpc_zec) = get_rpcs();
        let mut trade = get_trade_btc_to_zec(&rpc_btc, &rpc_zec);
        let mut trade_fulfiller = Trade::import(trade.export()).unwrap();
        println!("Trade: {}", trade);
        trade.init(&rpc_btc, &rpc_zec).unwrap();
        trade_fulfiller.init(&rpc_btc, &rpc_zec).unwrap();

        assert_eq!(trade.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), InitiatorInit);
        assert_eq!(trade_fulfiller.check(MINCONF, &rpc_btc, &rpc_zec).unwrap(), FulfillerInit);

        let fund_txid = trade.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Initiator fund txid: {}", fund_txid);

        let start_blocknum_btc = rpc_btc.getblockcount().unwrap();
        loop {
            let balance = trade_fulfiller.get_unredeemed_amount(minconf, &rpc_btc, &rpc_zec).unwrap();
            sleep(sleep_time);
            if rpc_btc.getblockcount().unwrap() >= (start_blocknum_btc + minconf) {
                break
            }
            println!("balance = {}, btc blockcount = {}", balance, rpc_btc.getblockcount().unwrap());
            assert_eq!(balance, 0.0);
            let stage = trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap();
            if rpc_btc.getblockcount().unwrap() >= (start_blocknum_btc + minconf) {
                break
            }
            assert_eq!(stage, FulfillerInit);
            sleep(sleep_time);
        }

        assert_eq!(trade_fulfiller.get_unredeemed_amount(minconf, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_BTC + 0.000_010);
        assert_eq!(trade.check(minconf, &rpc_btc, &rpc_zec).unwrap(), InitiatorFunded);
        assert_eq!(trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorFunded);

        let fulf_fund_txid = trade_fulfiller.fund(1000, &rpc_btc, &rpc_zec).unwrap();
        println!("Fulfiller fund txid: {}", fulf_fund_txid);
        let start_blocknum_zec = rpc_zec.getblockcount().unwrap();
        loop {
            let stage = trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap();
            if rpc_zec.getblockcount().unwrap() >= (start_blocknum_zec + minconf) {
                break
            }
            assert_eq!(stage, FulfillerInitiatorFunded);
            println!("zec blockcount = {}, need: {}", rpc_zec.getblockcount().unwrap(), start_blocknum_zec + minconf);
            sleep(sleep_time);
        }

        let mut count = 0;
        while trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap() != InitiatorFulfillerFunded {
            sleep(sleep_time);
            count = count + 1;
            if count == 5 {
                break;
            }
        }

        assert_eq!(trade.check(minconf, &rpc_btc, &rpc_zec).unwrap(), InitiatorFulfillerFunded);
        assert_eq!(trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap(), FulfillerFunded);
        assert_eq!(trade_fulfiller.get_unredeemed_amount(minconf, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_BTC + 0.000_010);
        assert_eq!(trade.get_unredeemed_amount(minconf, &rpc_btc, &rpc_zec).unwrap(), AMOUNT_ZEC + 0.000_010);

        let redeem_txid = trade.redeem(1000, minconf, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid: {}", redeem_txid);
        let start_blocknum_zec = rpc_zec.getblockcount().unwrap();
        loop {
            let stage = trade.check(minconf, &rpc_btc, &rpc_zec).unwrap();
            if rpc_zec.getblockcount().unwrap() >= (start_blocknum_zec + minconf) {
                break
            }
            assert_eq!(stage, InitiatorFulfillerFunded);
            println!("zec blockcount = {}, need: {}", rpc_zec.getblockcount().unwrap(), start_blocknum_zec + minconf);
            sleep(sleep_time);
        }

        match trade.refund(minconf, &rpc_btc, &rpc_zec) {
            Err(e) => match e {
                super::TradeError::RefundAttemptTooEarly{..} => panic!("Invalid redeem checking!"),
                super::TradeError::AlreadyRedeemed => {},
                super::TradeError::InvalidStage(_) => {},
                super::TradeError::Other(e) => panic!(e),
                _ => panic!("{}", e)
            }
            Ok(_) => {
                panic!("Invalid redeem checking!");
            }
        }
        assert_eq!(trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap(), FulfillerInitiatorRedeemed);

        let redeem_txid_fulfiller = trade_fulfiller.redeem(1000, minconf, &rpc_btc, &rpc_zec).unwrap();
        println!("Redeem txid fulfiller: {}", redeem_txid_fulfiller);
        let start_blocknum_btc = rpc_btc.getblockcount().unwrap();
        loop {
            let stage = trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap();
            if rpc_btc.getblockcount().unwrap() >= (start_blocknum_btc + minconf) {
                break
            }
            assert_eq!(stage, FulfillerInitiatorRedeemed);
            println!("btc blockcount = {}, need: {}", rpc_btc.getblockcount().unwrap(), start_blocknum_btc + minconf);
            sleep(sleep_time);
        }

        let mut count = 0;
        while trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap() != FulfillerComplete {
            sleep(sleep_time);
            count = count + 1;
            if count == 10 {
                break;
            }
        }

        assert_eq!(trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade_fulfiller.check(minconf, &rpc_btc, &rpc_zec).unwrap(), FulfillerComplete);
        assert_eq!(trade.check(minconf, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
        assert_eq!(trade.check(minconf, &rpc_btc, &rpc_zec).unwrap(), InitiatorComplete);
    }

    #[test]
    fn serde_blank() {
        let secp = secp256k1::Secp256k1::new();
        let bid = TradeBlankCurParams {
            amount: Some(1.1),
            locktime: None,
            max_fee: None,
            confirmation_height: None
        };
        let params = TradeBlankParameters::BtcToZec(
            TradeBlankParams {
                buy: Some(bid),
                sell: None
            }
        );
        let addr_btc = BtcAddress::from_str("2N2RVjgcU1dK2kKCU4iQ19JugD23G5XE2QG").unwrap();
        let addr_zec = ZecAddress::from_str("tmZ3ncCDJ961XUqGgk8oXn6wsJz6aeXHd4z").unwrap();
        let mut privkey_btc = bitcoin::util::base58::from_check(&"cMueW443y5DpvyBqvyKA8FmYS8DrMotg4gqrnGzaMBNHhWyHFGh3").unwrap();
        privkey_btc.pop();
        privkey_btc.remove(0);
        let privkey_btc = secp256k1::key::SecretKey::from_slice(&secp, privkey_btc.as_slice()).unwrap();
        let mut privkey_zec = bitcoin::util::base58::from_check(&"cPysi1qXEN4EHjsFy2YPdEzkV5RhsFJrXt7eVw1EwC87JK7GUvcW").unwrap();
        privkey_zec.pop();
        privkey_zec.remove(0);
        let privkey_zec = secp256k1::key::SecretKey::from_slice(&secp, privkey_zec.as_slice()).unwrap();
        let initiator = TradeBlankParticipant {
            addr_btc: Some(addr_btc),
            addr_zec: Some(addr_zec),
            privkey_btc: Some(privkey_btc),
            privkey_zec: Some(privkey_zec),
        };
        let fulfiller = TradeBlankParticipant {
            addr_btc: None,
            addr_zec: None,
            privkey_btc: None,
            privkey_zec: None,
        };
        let blank = TradeBlank {
            id: "TestBlank".into(),
            params: Some(params),
            role: Role::Initiator,
            secret: None,
            secret_hash: None,
            initiator: initiator,
            fulfiller: fulfiller
        };
        let serialized = serde_json::to_string_pretty(&blank).unwrap();
        let deserialized: TradeBlank = serde_json::from_str(&serialized).unwrap();
        let serialized_again = serde_json::to_string_pretty(&deserialized).unwrap();
        println!("Blank: {}", serde_json::to_string_pretty(&deserialized).unwrap());
        assert_eq!(serialized, serialized_again);
    }
}
