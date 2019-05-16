#[macro_use] extern crate serde_derive;
extern crate libswas;
extern crate bitcoin;
extern crate bitcoin_zcash;
extern crate serde;
extern crate serde_json;
extern crate exonum_bitcoinrpc_zec_exp;
extern crate toml;
extern crate dirs;
extern crate base16;
extern crate secp256k1;
extern crate crypto;
extern crate rustc_serialize;
extern crate tempdir;
extern crate leveldb;
extern crate spinner;

use std::env;
use std::fs::File;
use std::str::FromStr;
use std::io::prelude::*;
use std::io::{self, BufRead, Write};
use std::path::Path;
use rustc_serialize::hex::{FromHex, ToHex};
use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::{Options, WriteOptions, ReadOptions};
use libswas::swas::{Trade, TradeError, Txid, Currency, Currency::{*}, TradeBlank, TradeBlankParams,
                     TradeBlankParameters, TradeBlankCurParams, Stage::{*}, Role};
use exonum_bitcoinrpc_zec_exp::Client as RpcClient;
use bitcoin::util::base58;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use spinner::{SpinnerBuilder, SpinnerHandle};

const CONFIRMATIONS_MIN: u64 = 6;
const LOCKTIME_BUY: u64 = 30;
const LOCKTIME_SELL: u64 = 60;

fn main() {
    let blank;
    let config = read_conf();
    let mut args: Vec<String> = env::args().collect();
    let (rpc_btc, rpc_zec) = get_rpcs(&config);
    let ldb_path;
    if args.len() > 1 {
        if args[args.len() - 1] == "fulftest" {
            println!("Hello from atomic swap demo (fulfiller test)!");
                ldb_path = String::from(dirs::home_dir().unwrap().to_string_lossy()) + ("/.swas/trades_fulfiller.ldb");
            args.pop().unwrap();
        } else {
            ldb_path = String::from(dirs::home_dir().unwrap().to_string_lossy()) + ("/.swas/trades.ldb");
            println!("Hello from atomic swap demo!");
        }
    } else {
        println!(r#"
Supported argumets:
    newtrade <tradename>
    exporttrade <tradename>
    importtrade <base68-check string>
    listtrades
    tradeinfo <tradename>
    autopilot <tradename>"#);
        return
    }
    let ldb_path = Path::new(&ldb_path);
    let mut options = Options::new();
    options.create_if_missing = true;
    let database : Database<i32> = match Database::open(ldb_path, options) {
        Ok(db) => { db },
        Err(e) => { panic!("failed to open database: {:?}", e) }
    };
    let mut db_len = 0;
    for i in 0..100 {
        match database.get(ReadOptions::new(), i).unwrap() {
            Some(_) => {
            },
            None => {
                db_len = i;
                break;
            }
        };
    };
    if args.len() > 1 {
        match args[1].as_ref() {
            "newtrade" => {
                if args.len() != 3 {
                    println!(r#"
                                newtrade usage:
                                    swas-demo newtrade tradename
                                Exit."#);
                    return;
                }
                blank = tradeblank_user_input(&config, args[2].to_string(), &rpc_btc, &rpc_zec);
                let swas = blank.into_trade().unwrap();
                let trade_state = TradeState::new(swas);
                println!("Trade: {}", trade_state.to_string_pretty_trade());
                save_trade_state(&trade_state, &database, db_len);
                println!("Trade saved.");
                return
            },
            "checktrade" => {
                if args.len() != 3 {
                    println!(r#"
                                checktrade usage:
                                    swas-demo checkctrade tradename
                                Exit."#);
                    return
                }
                let tradename = args[2].to_string();
                let mut trade_state = match get_trade_state_for_id(tradename.clone(), &database, db_len) {
                    None => {
                        println!("Trade {} not founded. Exit.", tradename);
                        return;
                    },
                    Some(trade_state) => trade_state
                };
                println!("Trade {} founded: {}", tradename, &trade_state.to_string_pretty_trade());

                let mut curr_stage = trade_state.swas.get_stage();
                if curr_stage == InitiatorUndef || curr_stage == FulfillerUndef {
                    trade_state.swas.init(&rpc_btc, &rpc_zec).unwrap();
                }
                loop {
                    let conf_min = if trade_state.swas.get_stage() == FulfillerFunded {
                        0
                    } else {
                        config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)
                    };
                    if curr_stage == trade_state.swas.check(conf_min, &rpc_btc, &rpc_zec).unwrap() {
                        break
                    } else {
                        curr_stage = trade_state.swas.get_stage();
                    }
                }
                dotrade(&config, &mut trade_state, &rpc_btc, &rpc_zec);
                save_trade_state(&trade_state, &database, db_len);
                println!("Trade stage: {:?}", trade_state.swas.get_stage());
                return;
            },
            "exporttrade" => {
                if args.len() != 3 {
                    println!(r#"
                                exporttrade usage:
                                    swas-demo exporttrade tradename
                                Exit."#);
                    return
                }
                let tradename = args[2].to_string();
                let trade_state = match get_trade_state_for_id(tradename.clone(), &database, db_len) {
                    None => {
                        println!("Trade {} not founded. Exit.", tradename);
                        return;
                    },
                    Some(trade_state) => trade_state
                };
                let trade_export_string = trade_export(&trade_state.swas.without_secret());
                println!("Send this string to fulfiller: \n{}", trade_export_string);
                return
            },
            "importtrade" => {
                if args.len() != 3 {
                    println!(r#"
                                importtrade usage:
                                    swas-demo importtrade tradestring
                                Exit."#);
                    return
                }
                let trade_export_string = args[2].to_string();
                let swas = trade_import(trade_export_string);
                let trade_state = TradeState::new(swas.clone());
                save_trade_state(&trade_state, &database, db_len);
                println!("Imported: {}", swas);
                return
            },
            "listtrades"=> {
                for i in 0..db_len {
                    match database.get( ReadOptions::new(), i).unwrap() {
                        Some(trade_state_vec_local) => {
                            let base58 = String::from_utf8(trade_state_vec_local).unwrap();
                            let trade_state_vec = bitcoin::util::base58::from_check(&base58).unwrap();
                            let trade_state = TradeState::from_string(String::from_utf8(trade_state_vec).unwrap()).unwrap();
                            println!("-------------------------------");
                            println!("Trade name: {}", trade_state.swas.get_id());
                            println!("Buy: {} {:?}", trade_state.swas.get_amount_buy(), trade_state.swas.get_currency_buy());
                            println!("Sell: {} {:?}", trade_state.swas.get_amount_sell(), trade_state.swas.get_currency_sell());
                            println!("Role: {:?}", trade_state.swas.get_role());
                            print!("Stage: ");
                            match trade_state.swas.get_stage() {
                                InitiatorUndef => println!("Not initialized"),
                                InitiatorInit => println!("Initialized"),
                                InitiatorFunded => println!("Funded"),
                                InitiatorFulfillerFunded => println!("Fulfiller funded"),
                                InitiatorComplete => println!("Complete (redeemed)"),
                                InitiatorRefunded => println!("Refunded"),
                                FulfillerUndef => println!("Not initialized"),
                                FulfillerInit => println!("Initialized"),
                                FulfillerInitiatorFunded => println!("Initiator funded"),
                                FulfillerFunded => println!("Funded"),
                                FulfillerInitiatorRedeemed => println!("Initiator redeemed"),
                                FulfillerComplete => println!("Complete (redeemed)"),
                                FulfillerRefunded => println!("Refunded"),
                            }
                        },
                        None => {}
                    };
                }
            },
            "autopilot" => {
                if args.len() != 3 {
                    println!(r#"
                                autopilot usage:
                                    swas-demo autopilot <tradename>
                                Exit."#);

                    return
                }
                let trade_name = args[2].to_string();
                let mut trade_state = match get_trade_state_for_id(trade_name.clone(), &database, db_len) {
                    None => {
                        println!("Trade {} not founded. Exit.", trade_name);
                        return;
                    },
                    Some(trade_state) => trade_state
                };
                println!("Trade {}: {}", trade_name, &trade_state.to_string_pretty());
                let spinner_message = format!(r#"Executing swas "{}":"#, trade_name);
                let sp = SpinnerBuilder::new(spinner_message.clone().into()).start();
                sp.message(spinner_message.into());
                sp.update("Init...".into());
                autopilot(&config, &sp, &mut trade_state, &database, db_len, &rpc_btc, &rpc_zec);
                return
            },
            "tradeinfo" => {
                if args.len() != 3 {
                    println!(r#"
                                tradeinfo usage:
                                    swas-demo tradeinfo tradename
                                Exit."#);
                    return
                }
                let tradename = args[2].to_string();
                let trade_state = match get_trade_state_for_id(tradename.clone(), &database, db_len) {
                    None => {
                        println!("Trade {} not founded. Exit.", tradename);
                        return;
                    },
                    Some(trade_state) => trade_state
                };
                println!("Trade {}: {}", trade_state.swas.get_id(), trade_state.swas);
                println!("Role: {:?}", trade_state.swas.get_role());
                print!("Stage: ");
                match trade_state.swas.get_stage() {
                    InitiatorUndef => println!("Not initialized"),
                    InitiatorInit => println!("Initialized"),
                    InitiatorFunded => println!("Funded"),
                    InitiatorFulfillerFunded => println!("Fulfiller funded"),
                    InitiatorComplete => println!("Complete (redeemed)"),
                    InitiatorRefunded => println!("Refunded"),
                    FulfillerUndef => println!("Not initialized"),
                    FulfillerInit => println!("Initialized"),
                    FulfillerInitiatorFunded => println!("Initiator funded"),
                    FulfillerFunded => println!("Funded"),
                    FulfillerInitiatorRedeemed => println!("Initiator redeemed"),
                    FulfillerComplete => println!("Complete (redeemed)"),
                    FulfillerRefunded => println!("Refunded"),
                }
                match trade_state.swas.get_role() {
                    Role::Initiator => {
                        match trade_state.get_initiator_fund_txid_string() {
                            Some(txid) => println!("Fund txid: {}", txid),
                            None => {},
                        };
                        match trade_state.get_initiator_redeem_txid_string() {
                            Some(txid) => println!("Redeem txid: {}", txid),
                            None => {},
                        };
                        match trade_state.get_inititator_refund_txid_string() {
                            Some(txid) => println!("Refund txid: {}", txid),
                            None => {},
                        };
                    },
                    Role::Fulfiller => {
                        match trade_state.get_fulfiller_fund_txid_string(){
                            Some(txid) => println!("Fund txid: {}", txid),
                            None => {},
                        };
                        match trade_state.get_fulfiller_redeem_txid_string() {
                            Some(txid) => println!("Redeem txid: {}", txid),
                            None => {},
                        };
                        match trade_state.get_fulfiller_refund_txid_string() {
                            Some(txid) => println!("Refund txid: {}", txid),
                            None => {},
                        };
                    }
                }
                let v = trade_state.swas.concensus_encode();
                let s = v.to_hex();
                println!("Serialized:\n{}", s);
                let n = bitcoin::util::base58::check_encode_slice(&v);
                println!("Encoded:\n{}", n);
            }
            _ => {
                println!(r#"Supported argumets:
                            newtrade
                            exporttrade
                            importtrade
                            listtrades
                            autopilot
                            tradeinfo"#);
                return
            }
        }
    }
}

#[derive(Deserialize)]
struct Config {
    btcrpcport: Option<u32>,
    btcrpcuser: Option<String>,
    btcrpcpassword: Option<String>,
    zecrpcport: Option<u32>,
    zecrpcuser: Option<String>,
    zecrpcpassword: Option<String>,
    minconfirmaions: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
struct TradeState {
    pub swas: Trade,
    initiator_fund_txid: Option<Txid>,
    fulfiller_fund_txid: Option<Txid>,
    initiator_redeem_txid: Option<Txid>,
    fulfiller_redeem_txid: Option<Txid>,
    inititator_refund_txid: Option<Txid>,
    fulfiller_refund_txid: Option<Txid>,
}

impl TradeState {
    fn new(swas: Trade) -> TradeState {
        TradeState {
            swas: swas,
            initiator_fund_txid: None,
            fulfiller_fund_txid: None,
            initiator_redeem_txid: None,
            fulfiller_redeem_txid: None,
            inititator_refund_txid: None,
            fulfiller_refund_txid: None,
        }
    }

    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }

    fn to_string_pretty_trade(&self) -> String {
        format!("{}", self.swas)
    }

    fn from_string(s: String) -> Result<TradeState, String> {
        match serde_json::from_str::<TradeState>(&s) {
            Ok(realtradestate) => Ok(realtradestate),
            Err(err) => Err(err.to_string())
        }
    }

    fn get_id(&self) -> String {
        self.swas.get_id()
    }

    fn add_initiator_fund_txid(&mut self, txid: Txid) {
        self.initiator_fund_txid = match self.initiator_fund_txid {
            None => Some(txid),
            Some(_) => panic!("Double initiator_fund_txid")
        };
    }

    fn add_fulfiller_fund_txid(&mut self, txid: Txid) {
        self.fulfiller_fund_txid = match self.fulfiller_fund_txid {
            None => Some(txid),
            Some(_) => panic!("Double fulfiller_fund_txid")
        };
    }

    fn add_initiator_redeem_txid(&mut self, txid: Txid) {
        self.initiator_redeem_txid = match self.initiator_redeem_txid {
            None => Some(txid),
            Some(_) => panic!("Double initiator_redeem_txid")
        };
    }

    fn add_fulfiller_redeem_txid(&mut self, txid: Txid) {
        self.fulfiller_redeem_txid = match self.fulfiller_redeem_txid {
            None => Some(txid),
            Some(_) => panic!("Double fulfiller_redeem_txid")
        };
    }

    #[allow(dead_code)]
    fn add_inititator_refund_txid(&mut self, txid: Txid) {
        self.inititator_refund_txid = match self.inititator_refund_txid {
            None => Some(txid),
            Some(_) => panic!("Double inititator_refund_txid")
        };
    }

    #[allow(dead_code)]
    fn add_fulfiller_refund_txid(&mut self, txid: Txid) {
        self.fulfiller_refund_txid = match self.fulfiller_refund_txid {
            None => Some(txid),
            Some(_) => panic!("Double fulfiller_refund_txid")
        };
    }

    fn get_initiator_fund_txid_string(&self) -> Option<String> {
        match &self.initiator_fund_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_fulfiller_fund_txid_string(&self) ->  Option<String> {
        match &self.fulfiller_fund_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_initiator_redeem_txid_string(&self) ->  Option<String> {
        match &self.initiator_redeem_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_fulfiller_redeem_txid_string(&self) ->  Option<String> {
        match &self.fulfiller_redeem_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_inititator_refund_txid_string(&self) -> Option<String> {
        match &self.inititator_refund_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_fulfiller_refund_txid_string(&self) -> Option<String> {
        match &self.fulfiller_refund_txid {
            Some(txid) => Some(Self::get_txid_string(txid)),
            None => None
        }
    }

    fn get_initiator_fund_txid(&self) -> Option<Txid> {
        self.initiator_fund_txid.clone()
    }

    fn get_fulfiller_fund_txid(&self) -> Option<Txid> {
        self.fulfiller_fund_txid.clone()
    }

    fn get_initiator_redeem_txid(&self) -> Option<Txid> {
        self.initiator_redeem_txid.clone()
    }

    fn get_fulfiller_redeem_txid(&self) -> Option<Txid> {
        self.fulfiller_redeem_txid.clone()
    }

    #[allow(dead_code)]
    fn get_inititator_refund_txid(&self) -> Option<Txid> {
        self.inititator_refund_txid.clone()
    }

    #[allow(dead_code)]
    fn get_fulfiller_refund_txid(&self) -> Option<Txid> {
        self.fulfiller_refund_txid.clone()
    }

    fn conv_btc_tx(h: &bitcoin::util::hash::Sha256dHash) -> String {
        let bytes = h.to_bytes().to_vec();
        bytes.to_hex()
    }

    fn conv_zec_tx(h: &bitcoin_zcash::util::hash::Sha256dHash) -> String {
        let bytes = h.to_bytes().to_vec();
        bytes.to_hex()
    }

    fn get_txid_string(txid: &Txid) -> String {
        match txid {
            Txid::Btc(ref txid) => {
                format!("Bitcoin '{}'", Self::conv_btc_tx(txid))
            },
            Txid::Zec(ref txid) => {
                format!("Zcash '{}'", Self::conv_zec_tx(txid))
            }
        }
    }

    fn get_confirmations(txid: &Txid, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match txid {
            Txid::Btc(txid) => {
                match rpc_btc.gettransaction(&format!("{}", &Self::conv_btc_tx(txid))) {
                    Ok(transactioninfo) => transactioninfo.confirmations,
                    Err(err) => panic!("rpc_btc.gettransaction({}): {}", &format!("{}", &Self::conv_btc_tx(txid)), err)
                }
            },
            Txid::Zec(txid) => {
                match rpc_zec.gettransaction_zec(&format!("{}", &Self::conv_zec_tx(txid))) {
                    Ok(transactioninfo) => transactioninfo.confirmations,
                    Err(err) => panic!("rpc_btc.gettransaction({}): {}", &format!("{}", &Self::conv_zec_tx(txid)), err)
                }
            }
        }
    }

    fn get_confirmations_initiator_fund_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.initiator_fund_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }

    fn get_confirmations_fulfiller_fund_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.fulfiller_fund_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }

    fn get_confirmations_initiator_redeem_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.initiator_redeem_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }

    fn get_confirmations_fulfiller_redeem_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.fulfiller_redeem_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }

    #[allow(dead_code)]
    fn get_confirmations_inititator_refund_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.inititator_refund_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }

    #[allow(dead_code)]
    fn get_confirmations_fulfiller_refund_txid(&self, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> u64 {
        match &self.fulfiller_refund_txid {
            Some(txid) => Self::get_confirmations(txid, rpc_btc, rpc_zec),
            None => panic!("tx does not exist ")
        }
    }
}

#[derive(PartialEq)]
enum UserActions {
    Proceed,
    Cancel,
    #[allow(dead_code)]
    Exit
}

fn autopilot(config: &Config, sp: &SpinnerHandle, trade_state: &mut TradeState,  database: &Database<i32>, db_len: i32,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) {
    use std::{thread::sleep, time};
    let sleep_time_after = time::Duration::from_secs(2);
    let role = trade_state.swas.get_role();
    loop {
        let stage = trade_state.swas.get_stage();
        let conf_min = if stage == FulfillerFunded ||
                          stage == FulfillerComplete ||
                          stage == InitiatorComplete ||
                          stage == InitiatorFulfillerFunded ||
                          stage == FulfillerInitiatorRedeemed {
            0
        } else {
            config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)
        };
        trade_state.swas.check(conf_min, &rpc_btc, &rpc_zec).unwrap();
        save_trade_state(trade_state, database, db_len);
        //sp.update("Check...".into());
        //println!("Role: {:?}", role);
        //println!("Stage: {:?}", trade_state.swas.get_stage());
        match &role {
            Role::Initiator => autopilot_initiator(config, sp, trade_state, rpc_btc, rpc_zec),
            Role::Fulfiller => autopilot_fulfiller(config, sp, trade_state, rpc_btc, rpc_zec)
        }
        sleep(sleep_time_after);
    }
}

fn autopilot_initiator(config: &Config, sp: &SpinnerHandle, trade_state: &mut TradeState,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) {
    match trade_state.swas.get_stage() {
        InitiatorUndef => {
            stage_initiator_undef(true, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        InitiatorInit => {
            match trade_state.get_initiator_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_initiator_fund_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        sp.update(format!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)).into());
                        return;
                    }
                },
                _ => {}
            }
            match trade_state.swas.check(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), rpc_btc, rpc_zec).unwrap() {
                InitiatorInit => {
                    let (ua, txid) = stage_initiator_init(true, &mut trade_state.swas, rpc_btc, rpc_zec);
                    if ua == UserActions::Cancel {
                        return
                    }
                    let txid_init_fund = get_txid(txid, trade_state.swas.get_currency_sell());
                    trade_state.add_initiator_fund_txid(txid_init_fund);
                }
                _ => {}
            }
        },
        InitiatorFunded => {
            sp.update("Waiting fulfiller to fund contract...                                                                                    ".into());
            stage_initiator_funded(true, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        InitiatorFulfillerFunded => {
            sp.update("Fulfiller funded contract!                                                                                               ".into());
            let (ua, txid) = stage_initiator_fulfillerfunded(config, true, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_init_redeemed = get_txid(txid.unwrap(), trade_state.swas.get_currency_buy());
            trade_state.add_initiator_redeem_txid(txid_init_redeemed);
        },
        InitiatorComplete => {
            match trade_state.get_initiator_redeem_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_initiator_redeem_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        sp.update(format!("Waiting our redeem tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)).into());
                        return;
                    } else {
                        let redeem_txid = match &trade_state.get_initiator_redeem_txid_string() {
                            Some(tx) => tx.clone(),
                            None => "undefined".to_string()
                        };
                        sp.update(format!("Deal finished! Redeem Txid: {}, confirmations: {}    ", redeem_txid, conf_num).into());
                    }
                },
                _ => {panic!("1")}
            }
        },
        InitiatorRefunded => {
        },
        _ => {unreachable!()}
    }
}

fn autopilot_fulfiller(config: &Config, sp: &SpinnerHandle, trade_state: &mut TradeState,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) {
    match trade_state.swas.get_stage() {
        FulfillerUndef => {
            stage_fulfiller_undef(true, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        FulfillerInit => {
            sp.update("Waiting initiator to fund contract...                                                                         ".into());
            stage_fulfiller_init(true, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        FulfillerInitiatorFunded => {
            match trade_state.get_fulfiller_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_fund_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        sp.update(format!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)).into());
                        return;
                    }
                },
                _ => {}
            }
            match trade_state.swas.check(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), rpc_btc, rpc_zec).unwrap() {
                FulfillerInitiatorFunded => {
                    let (ua, txid) = stage_fulfiller_initiatorfunded(true, &mut trade_state.swas, rpc_btc, rpc_zec);
                    if ua == UserActions::Cancel {
                        return
                    }
                    let txid_fulf_fund = get_txid(txid, trade_state.swas.get_currency_sell());
                    trade_state.add_fulfiller_fund_txid(txid_fulf_fund);
                },
                _ => {}
            }
        },
        FulfillerFunded => {
            match trade_state.get_fulfiller_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_fund_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        sp.update(format!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)).into());
                        return;
                    }
                },
                _ => {}
            }
            match trade_state.swas.check(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), rpc_btc, rpc_zec).unwrap() {
                FulfillerFunded => {
                    stage_fulfiller_funded(true, &mut trade_state.swas, rpc_btc, rpc_zec);
                },
                _ => {}
            }
        },
        FulfillerInitiatorRedeemed => {
            sp.update("Initiator redeemed contract!                                                                                             ".into());
            let (ua, txid) = stage_fulfiller_initiatorredeemed(true, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_fulf_redeemed = get_txid(txid, trade_state.swas.get_currency_buy());
            trade_state.add_fulfiller_redeem_txid(txid_fulf_redeemed);
        },
        FulfillerComplete => {
            match trade_state.get_fulfiller_redeem_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_redeem_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        sp.update(format!("Waiting our redeem tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN)).into());
                        return;
                    } else {
                        let redeem_txid = match &trade_state.get_fulfiller_redeem_txid_string()  {
                            Some(tx) => tx.clone(),
                            None => "undefined".to_string()
                        };
                        sp.update(format!("Deal finished! Redeem Txid: {}, confirmations: {}    ", redeem_txid, conf_num).into());
                    }
                },
                _ => {}
            }
        },
        FulfillerRefunded => {},
        _ => {unreachable!()}
    }
}

fn dotrade(config: &Config, trade_state: &mut TradeState,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) {
    match trade_state.swas.get_stage() {
        InitiatorUndef => {
            stage_initiator_undef(false, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        InitiatorInit => {
            match trade_state.get_initiator_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_initiator_fund_txid(rpc_btc, rpc_zec);
                    if conf_num <= config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        println!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN));
                        return;
                    }
                },
                _ => {}
            }
            let (ua, txid) = stage_initiator_init(false, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_init_fund = get_txid(txid, trade_state.swas.get_currency_sell());

            trade_state.add_initiator_fund_txid(txid_init_fund);
        },
        InitiatorFunded => {
            stage_initiator_funded(false, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        InitiatorFulfillerFunded => {
            let (ua, txid) = stage_initiator_fulfillerfunded(config, false, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_init_redeemed = get_txid(txid.unwrap(), trade_state.swas.get_currency_buy());
            trade_state.add_initiator_redeem_txid(txid_init_redeemed);
        },
        InitiatorComplete => {
            match trade_state.get_initiator_redeem_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_initiator_redeem_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        println!("Waiting our redeem tx confirmation: {} transaction have {} confirmations (need {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN));
                        return;
                    }
                },
                _ => {}
            }
            let redeem_txid = match &trade_state.get_initiator_redeem_txid_string() {
                Some(tx) => tx.clone(),
                None => "undefined".to_string()
            };
            stage_initiator_complete(&mut trade_state.swas, &redeem_txid, rpc_btc, rpc_zec);
        },
        InitiatorRefunded => {
        },
        FulfillerUndef => {
            stage_fulfiller_undef(false, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        FulfillerInit => {
            stage_fulfiller_init(false, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        FulfillerInitiatorFunded => {
            match trade_state.get_fulfiller_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_fund_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        println!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN));
                        return;
                    }
                },
                _ => {}
            }
            let (ua, txid) = stage_fulfiller_initiatorfunded(false, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_fulf_fund = get_txid(txid, trade_state.swas.get_currency_sell());
            trade_state.add_fulfiller_fund_txid(txid_fulf_fund);
        },
        FulfillerFunded => {
            match trade_state.get_fulfiller_fund_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_fund_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        println!("Waiting our fund tx confirmation: {} ({} of {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN));
                        return;
                    }
                },
                _ => {}
            }
            stage_fulfiller_funded(false, &mut trade_state.swas, rpc_btc, rpc_zec);
        },
        FulfillerInitiatorRedeemed => {
            let (ua, txid) = stage_fulfiller_initiatorredeemed(false, &mut trade_state.swas, rpc_btc, rpc_zec);
            if ua == UserActions::Cancel {
                return
            }
            let txid_fulf_redeemed = get_txid(txid, trade_state.swas.get_currency_buy());
            trade_state.add_fulfiller_redeem_txid(txid_fulf_redeemed);
        },
        FulfillerComplete => {
            match trade_state.get_fulfiller_redeem_txid() {
                Some(txid) => {
                    let conf_num = trade_state.get_confirmations_fulfiller_redeem_txid(rpc_btc, rpc_zec);
                    if conf_num < config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN) {
                        println!("Waiting our redeem tx confirmation: {} transaction have {} confirmations (need {})",
                                txid,
                                conf_num,
                                config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN));
                        return;
                    }
                },
                _ => {}
            }
            let redeem_txid = match &trade_state.get_fulfiller_redeem_txid_string()  {
                Some(tx) => tx.clone(),
                None => "undefined".to_string()
            };;
            stage_fulfiller_complete(false, &mut trade_state.swas, &redeem_txid, &rpc_btc, &rpc_zec);
        },
        FulfillerRefunded => {},
    }
}

fn get_txid(txid: String, currency: Currency) -> Txid {
    match currency {
        Bitcoin => Txid::Btc(bitcoin::util::hash::Sha256dHash::from({
                let mut txid = txid.from_hex().unwrap();
                txid.reverse();
                txid
            }.as_slice())),
        Zcash => Txid::Zec(bitcoin_zcash::util::hash::Sha256dHash::from({
                let mut txid = txid.from_hex().unwrap();
                txid.reverse();
                txid
            }.as_slice()))
    }
}

fn save_trade_state(trade_state: &TradeState, database: &Database<i32>, db_len: i32) -> i32 {
    let mut trade_num: Option<i32> = None;
    for i in 0..db_len {
        match database.get( ReadOptions::new(), i).unwrap() {
            Some(trade_vec_local) => {
                let base58 = String::from_utf8(trade_vec_local).unwrap();
                let trade_state_vec = bitcoin::util::base58::from_check(&base58).unwrap();
                let trade_state_curr = TradeState::from_string(String::from_utf8(trade_state_vec).unwrap()).unwrap();
                if trade_state.get_id() == trade_state_curr.get_id() {
                    trade_num = Some(i)
                } else {
                    continue
                }
            },
            None => {}
        };
    }
    let mut write_opts = WriteOptions::new();
    let trade_state_string = trade_state.to_string();
    let trade_state_base16 = trade_state_string.into_bytes();
    let trade_state_base58_check = bitcoin::util::base58::check_encode_slice(&trade_state_base16);
    write_opts.sync = true;
    if trade_num == None {
        database.put(write_opts, db_len, &trade_state_base58_check.into_bytes()).unwrap();
        db_len + 1
    } else {
        database.put(write_opts, trade_num.unwrap(), &trade_state_base58_check.into_bytes()).unwrap();
        db_len
    }
}

fn trade_export(swas: &Trade) -> String {
    bitcoin::util::base58::check_encode_slice(&swas.export())
}

fn trade_import(trade_base58: String) -> Trade {
    let trade_vec = bitcoin::util::base58::from_check(&trade_base58).unwrap();
    Trade::import(trade_vec).unwrap()
}

fn get_trade_state_for_id(id: String, database: &Database<i32>, db_len: i32) -> Option<TradeState> {
    for i in 0..(db_len + 1) {
        match database.get( ReadOptions::new(), i).unwrap() {
            Some(trade_state_vec_local) => {
                let base58 = String::from_utf8(trade_state_vec_local).unwrap();
                let trade_state_vec = bitcoin::util::base58::from_check(&base58).unwrap();
                let trade_state = TradeState::from_string(String::from_utf8(trade_state_vec).unwrap()).unwrap();
                //println!("{}: {}", i, trade_state.to_string());
                if trade_state.get_id() == id {
                    return Some(trade_state)
                } else {
                    continue
                }
            },
            None => return None
        };
    }
    return None
}


fn stage_initiator_complete(_trade: &mut Trade,
        redeem_txid: &String,
        _rpc_btc: &RpcClient,
        _rpc_zec: &RpcClient) -> UserActions {
    println!("Deal finished! Redeem Txid: {}     ", redeem_txid);
    UserActions::Proceed
}

fn stage_initiator_fulfillerfunded(config: &Config, autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> (UserActions, Option<String>) {
    if autopilot == false {
        println!("Congratulations! Fulfiller funded contract!");
        println!("Available: {} {:?}", swas.get_unredeemed_amount(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), &rpc_btc, &rpc_zec).unwrap(), swas.get_currency_buy());
        println!("Trade was initialized. Redeem {} {:?}? [y/N]", swas.get_unredeemed_amount(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), &rpc_btc, &rpc_zec).unwrap(), swas.get_currency_sell());
        let send = readline_and_trim();
        if send == "y" || send == "Y" {
            let mut txid = Txid::Btc(bitcoin::util::hash::Sha256dHash::from(&[0u8; 32][..]));
            match swas.redeem(1000, 0, &rpc_btc, &rpc_zec) {
                Ok(txid_l) => {
                    let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                    println!("Done! Txid: {}", txid_s);
                    txid = txid_l;
                },
                Err(err) => {
                    match err {
                        TradeError::AlreadyRedeemed => {
                            println!("Already redeemed...");
                        },
                        _ => panic!("{:?}", err)
                    }
                }
            }
            (UserActions::Proceed, match txid {
                Txid::Btc(txid) => Some(txid.as_bytes().to_hex()),
                Txid::Zec(txid) => Some(txid.as_bytes().to_hex())
            })
        } else {
            (UserActions::Cancel, None)
        }
    } else {
        let available = swas.get_unredeemed_amount(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN), &rpc_btc, &rpc_zec).unwrap();
        let needed = swas.get_amount_buy();
        if available >= needed {
            let mut txid = Txid::Btc(bitcoin::util::hash::Sha256dHash::from(&[0u8; 32][..]));
            match swas.redeem(1000, 0, &rpc_btc, &rpc_zec) {
                Ok(txid_l) => {
                    //let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                    //println!("Redeemed! Txid: {}", txid_s);
                    txid = txid_l;
                },
                Err(err) => {
                    match err {
                        TradeError::AlreadyRedeemed => {
                            println!("Already redeemed...");
                        },
                        _ => panic!("{:?}", err)
                    }
                }
            }
            (UserActions::Proceed, match txid {
                Txid::Btc(txid) => Some(txid.as_bytes().to_hex()),
                Txid::Zec(txid) => Some(txid.as_bytes().to_hex())
            })
        } else {
            println!("Too little money on fulfiller p2sh: {}, need: {}", available, needed);
            (UserActions::Proceed, None)
        }
    }
}

fn stage_initiator_funded(autopilot: bool, _trade: &mut Trade,
        _rpc_btc: &RpcClient,
        _rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Congratulations! You sent funds to contract!");
        println!("Please Waiting when your customer will sent his funds...");
    }
    UserActions::Proceed
}

fn stage_initiator_init(autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> (UserActions, String) {
    if autopilot == false {
        println!("Trade was initialized. Send funds to contract? [Y/n]");
        let send = readline_and_trim();
        if send != "n" && send != "N" {
            let txid;
            match swas.fund(1000, &rpc_btc, &rpc_zec) {
                Ok(txid_l) => {
                    let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                    println!("Done! Txid: {}", txid_s);
                    txid = txid_l;
                },
                Err(err) => {
                    match err {
                        _ => panic!("{:?}", err)
                    }
                }
            };
            (UserActions::Proceed, match txid {
                Txid::Btc(txid) => txid.as_bytes().to_hex(),
                Txid::Zec(txid) => txid.as_bytes().to_hex()
            })
        } else {
            (UserActions::Cancel, [0u8; 32].to_hex())
        }
    } else {
        let txid;
        //println!("Send funds ({}{:?}) on p2sh...", swas.get_amount_sell(), swas.get_currency_sell());
        match swas.fund(1000, &rpc_btc, &rpc_zec) {
            Ok(txid_l) => {
                //let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                //println!("Done! Txid: {}", txid_s);
                txid = txid_l;
            },
            Err(err) => {
                match err {
                    _ => panic!("{:?}", err)
                }
            }
        };
        (UserActions::Proceed, match txid {
            Txid::Btc(txid) => txid.as_bytes().to_hex(),
            Txid::Zec(txid) => txid.as_bytes().to_hex()
        })
    }
}

fn stage_initiator_undef(autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Initializing swas...");
    }
    swas.init(&rpc_btc, &rpc_zec).unwrap();
    if autopilot == false {
        println!("Initialization complete successful.");
    }
    UserActions::Proceed
}

fn stage_fulfiller_complete(autopilot: bool,_trade: &mut Trade,
        redeem_txid: &String,
        _rpc_btc: &RpcClient,
        _rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Deal finished! Redeem Txid: {}     ", redeem_txid);
    }
    UserActions::Proceed
}

fn stage_fulfiller_initiatorredeemed(autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> (UserActions, String) {
    if autopilot == false {
        println!("Initiator redeemed!");
        println!("Secret: {}", swas.get_secret().unwrap().to_hex());
        println!("Redeem? [Y/n] ");
        let redeem = readline_and_trim();
        if redeem != "n" && redeem != "N" {
            let txid = swas.redeem(1000, 0, &rpc_btc, &rpc_zec).unwrap();
            let txid_s = serde_json::to_string_pretty(&txid).unwrap();
            println!("Done! Txid: {}", txid_s);
            (UserActions::Proceed, match txid {
                Txid::Btc(txid) => txid.as_bytes().to_hex(),
                Txid::Zec(txid) => txid.as_bytes().to_hex()
            })
        } else {
            (UserActions::Cancel, [0u8; 32].to_hex())
        }
    } else {
        let txid = swas.redeem(1000, 0, &rpc_btc, &rpc_zec).unwrap();
        //let txid_s = serde_json::to_string_pretty(&txid).unwrap();
        //println!("Done! Txid: {}", txid_s);
        (UserActions::Proceed, match txid {
            Txid::Btc(txid) => txid.as_bytes().to_hex(),
            Txid::Zec(txid) => txid.as_bytes().to_hex()
        })
    }
}

fn stage_fulfiller_funded(autopilot: bool, _trade: &mut Trade,
        _rpc_btc: &RpcClient,
        _rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Congratulations! You sent funds to contract!");
        println!("Please Waiting while initiator will redeem contract...");
    }
    UserActions::Proceed
}

fn stage_fulfiller_initiatorfunded(autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> (UserActions, String) {
    if autopilot == false {
    println!("Congratulations! Initiator sent funds to contract!");
        println!("Send funds to contract? [Y/n]");
        let send = readline_and_trim();
        if send != "n" && send != "N" {
            let txid;
            match swas.fund(1000, &rpc_btc, &rpc_zec) {
                Ok(txid_l) => {
                    let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                    println!("Done! Txid: {}", txid_s);
                    txid = txid_l;
                },
                Err(err) => {
                    match err {
                        _ => panic!("{:?}", err)
                    }
                }
            };
            (UserActions::Proceed,  match txid {
                Txid::Btc(txid) => txid.as_bytes().to_hex(),
                Txid::Zec(txid) => txid.as_bytes().to_hex()
            })
        } else {
            (UserActions::Cancel, [0u8; 32].to_hex())
        }
    } else {
        let txid;
        //println!("Send funds ({}{:?}) on p2sh...", swas.get_amount_sell(), swas.get_currency_sell());
        match swas.fund(1000, &rpc_btc, &rpc_zec) {
            Ok(txid_l) => {
                //let txid_s = serde_json::to_string_pretty(&txid_l).unwrap();
                //println!("Done! Txid: {}", txid_s);
                txid = txid_l;
            },
            Err(err) => {
                match err {
                    _ => panic!("{:?}", err)
                }
            }
        };
        (UserActions::Proceed,  match txid {
            Txid::Btc(txid) => txid.as_bytes().to_hex(),
            Txid::Zec(txid) => txid.as_bytes().to_hex()
        })
    }
}

fn stage_fulfiller_init(autopilot: bool, _trade: &mut Trade,
        _rpc_btc: &RpcClient,
        _rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Trade was initialized. Waiting initiator to send the funds...");
    }
    UserActions::Proceed
}

fn stage_fulfiller_undef(autopilot: bool, swas: &mut Trade,
        rpc_btc: &RpcClient,
        rpc_zec: &RpcClient) -> UserActions {
    if autopilot == false {
        println!("Initializing swas...");
    }
    swas.init(&rpc_btc, &rpc_zec).unwrap();
    if autopilot == false {
        println!("Initialization complete successful.");
    }
    UserActions::Proceed
}

#[allow(dead_code)]
fn print_trade(swas: & Trade) {
    println!("\nTrade: {}", serde_json::to_string_pretty(&swas).unwrap());

    //println!("\nTrade not pretty: {}", serde_json::to_string(&swas).unwrap());
    //let hex_string = base16::encode_lower(&serde_json::to_string(&swas).unwrap());
    //println!("\nTrade hex_string: {}", hex_string);
    //let base58_string = base58::check_encode_slice(serde_json::to_string(&swas).unwrap().as_ref());
    //println!("\nTrade base58_string: {}", base58_string);
}

fn read_conf() -> Config {
    let config_path = String::from(dirs::home_dir().unwrap().to_string_lossy()) + ("/.swas/swas.conf");
    let mut config_file = File::open(config_path).expect(r#"
        Config file not found ("~/.swas/swas.conf").
        Example:
            # swas.conf
            btcrpcport=18332
            btcrpcuser="username"
            btcrpcpassword="password"

            zecrpcport=18232
            zecrpcuser="username"
            zecrpcpassword="password"

            minconfirmaions=6
        "#);
    let mut config = String::new();
    config_file.read_to_string(&mut config).unwrap();
    toml::from_str(&config).unwrap()
}

fn readline_and_trim() -> String {
    let mut line = String::new();
    let stdin = io::stdin();
    io::stdout().flush().unwrap();
    stdin.lock().read_line(&mut line).expect("failed to read from stdin");
    line = line.trim().to_string();
    line
}

#[allow(dead_code)]
fn print_blank(blank: & TradeBlank) {
    println!("\nBlank: {}", blank_serialized = serde_json::to_string_pretty(&blank).unwrap());

    //println!("\nBlank not pretty: {}", serde_json::to_string(&blank).unwrap());
    //let hex_string = base16::encode_lower(&serde_json::to_string(&blank).unwrap());
    //println!("\nBlank hex_string: {}", hex_string);
    //let base58_string = base58::check_encode_slice(serde_json::to_string(&blank).unwrap().as_ref());
    //println!("\nBlank base58_string: {}", base58_string);
}

#[allow(dead_code)]
fn tradeblank_default(config: &Config, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> TradeBlank {
    let current_blockcount_btc = match rpc_btc.getblockcount() {
        Ok(blockcount) => blockcount - blockcount%100,
        Err(err) => panic!("rpc_btc.getblockcount(): {}", err)
    };
    let current_blockcount_zec = match rpc_zec.getblockcount() {
        Ok(blockcount) => blockcount - blockcount%100,
        Err(err) => panic!("rpc_zec.getblockcount(): {}", err)
    };

    let mut blank: TradeBlank = TradeBlank::new("demo".to_string(), Role::Initiator, None, None, None);
    let trade_direction: TradeBlankParameters;
    let trade_id = "default".to_string();
    let secp = secp256k1::Secp256k1::new();
    blank.initiator.addr_btc = Some(bitcoin::util::address::Address::from_str("n2c9zcyqHSXxegkAJD1WuCq1ewnnMx5fNU").unwrap());
    let mut privkey_btc = base58::from_check(&"cVU9ZG781HxWCT7dC9fG6fEMTreVYmPJT3FQ1YVPQdqsgzUewnEV").unwrap();
    privkey_btc.pop();
    privkey_btc.remove(0);
    blank.initiator.privkey_btc = Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_btc.as_slice()).unwrap());
    let mut privkey_zec = base58::from_check(&"cTWGnbL62kLopuiU7Kiw11ypYVLAq8wyjJRwiuAeJeDBLXivxxmR").unwrap();
    privkey_zec.pop();
    privkey_zec.remove(0);
    blank.initiator.privkey_zec = Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_zec.as_slice()).unwrap());
    blank.initiator.addr_zec = Some(bitcoin_zcash::util::address::Address::from_str("tmP4HYDkVQqfVP3eAt4aAcuvpGS9xh3Hp1b").unwrap());

    let mut privkey_btc = base58::from_check(&"cV8Ki1BfhArYPq2rKRdDTtWmKLm6VYJLmt7yp7vD5pGWYSuQxWX8").unwrap();
    privkey_btc.pop();
    privkey_btc.remove(0);
    blank.fulfiller.privkey_btc = Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_btc.as_slice()).unwrap());

    let mut privkey_zec = base58::from_check(&"cPZqhrupgx5rFwW82ritFJrAAPSCWjuD8xA4sthWgVWW6pHT1pVq").unwrap();
    privkey_zec.pop();
    privkey_zec.remove(0);
    blank.fulfiller.privkey_zec = Some(secp256k1::key::SecretKey::from_slice(&secp, privkey_zec.as_slice()).unwrap());

    blank.fulfiller.addr_btc = Some(bitcoin::util::address::Address::from_str("mqnARwaJVfKrE9RDdiQvw5aajk7zgqFbg1").unwrap());
    blank.fulfiller.addr_zec = Some(bitcoin_zcash::util::address::Address::from_str("tmCazwAKSjfi89CLgT2PDBG3MfpHGTCNagP").unwrap());
    let buy = TradeBlankCurParams {
        amount: Some(0.02),
        locktime: Some(current_blockcount_zec + 250),
        max_fee: Some(1000),
        confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
    };
    let sell = TradeBlankCurParams {
        amount: Some(0.01),
        locktime: Some(current_blockcount_btc + 500),
        max_fee: Some(1000),
        confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
    };
    trade_direction = TradeBlankParameters::BtcToZec(
        TradeBlankParams {
            buy: Some(buy),
            sell: Some(sell)
        }
    );
    blank.id = trade_id;
    blank.params = Some(trade_direction);
    blank.secret = Some([175, 51, 184, 251, 96, 66, 244, 231, 21, 81, 12, 203, 125, 15, 240, 172,
                         200, 207, 191, 196, 72, 10, 204, 91, 131, 161, 12, 4, 158, 156, 54, 73].to_vec());
    let mut hasher = Sha256::new();
    hasher.input(&blank.secret.clone().unwrap());
    let mut hash_result: [u8; 32] = [0; 32];
    hasher.result(&mut hash_result);
    blank.secret_hash = Some(hash_result);
    blank
}

fn tradeblank_user_input(config: &Config, trade_id: String, rpc_btc: &RpcClient, rpc_zec: &RpcClient) -> TradeBlank {
    let mut blank: TradeBlank = TradeBlank::new("demo".to_string(), Role::Initiator, None, None, None);
    let mut trade_direction = TradeBlankParameters::BtcToZec(TradeBlankParams {
        sell: None,
        buy: None
    });
    println!("Trade name: \"{}\"", trade_id);

    let mut addr_initiator_btc;
    println!("Enter your bitcoin address or press enter to generate new bitcoin address: ");
    loop {
        addr_initiator_btc = readline_and_trim();
        if addr_initiator_btc.len() == 0 {
            addr_initiator_btc = get_new_addr_btc(&rpc_btc, "swas_demo");
            println!("  Generated address: {}\n", addr_initiator_btc);
            let addr = bitcoin::util::address::Address::from_str(&addr_initiator_btc).unwrap();
            match addr.network {
                bitcoin::network::constants::Network::Bitcoin => {
                    println!("Only Testnet or Regtest currently supported! Exit.");
                    panic!("Only Testnet or Regtest.")
                },
                _ => {}
            }
            blank.initiator.addr_btc = Some(addr);
            break
        } else {
            match bitcoin::util::address::Address::from_str(&addr_initiator_btc) {
                Ok(addr) => {
                    match addr.network {
                        bitcoin::network::constants::Network::Bitcoin => {
                            println!("Only Testnet or Regtest currently supported! Exit.");
                            panic!("Only Testnet or Regtest.")
                        },
                        _ => {}
                    }
                    println!("Address {} accepted.\n", addr);
                    blank.initiator.addr_btc = Some(addr);
                    break
                }
                Err(_) => {
                    println!("Error: invalid bitcoin address. Try again:");
                    continue
                }
            }
        }
    }

    let mut addr_initiator_zec;
    println!("Enter your zcash address or press enter to generate new zcash address: ");
    loop {
        addr_initiator_zec = readline_and_trim();
        if addr_initiator_zec.len() == 0 {
            addr_initiator_zec = get_new_addr_zec(&rpc_zec);
            println!("  Generated address: {}\n", addr_initiator_zec);
            let addr = bitcoin_zcash::util::address::Address::from_str(&addr_initiator_zec).unwrap();
            match addr.network {
                bitcoin_zcash::network::constants::Network::Bitcoin => {
                    println!("Only Testnet or Regtest currently supported! Exit.");
                    panic!("Only Testnet or Regtest.")
                },
                _ => {}
            }
            blank.initiator.addr_zec = Some(addr);
            break
        } else {
            match bitcoin_zcash::util::address::Address::from_str(&addr_initiator_zec) {
                Ok(addr) => {
                    match addr.network {
                        bitcoin_zcash::network::constants::Network::Bitcoin => {
                            println!("Only Testnet or Regtest currently supported! Exit.");
                            panic!("Only Testnet or Regtest.")
                        },
                        _ => {}
                    }
                    println!("Address {} accepted.\n", addr);
                    blank.initiator.addr_zec = Some(addr);
                    break
                }
                Err(_) => {
                    println!("Error: invalid zcash address. Try again:");
                    continue
                }
            }
        }
    }

    let mut addr_fulfiller_btc;
    println!("Enter bitcoin address of the party you want to swas with: ");
    loop {
        addr_fulfiller_btc = readline_and_trim();
        match bitcoin::util::address::Address::from_str(&addr_fulfiller_btc) {
            Ok(addr) => {
                match addr.network {
                    bitcoin::network::constants::Network::Bitcoin => {
                        println!("Only Testnet or Regtest currently supported! Exit.");
                        panic!("Only Testnet or Regtest.")
                    },
                    _ => {}
                }
                println!("Address {} accepted.\n", addr);
                blank.fulfiller.addr_btc = Some(addr);
                break
            }
            Err(_) => {
                println!("Error: invalid bitcoin address. Try again:");
                continue
            }
        }
    }

    let mut addr_fulfiller_zec;
    println!("Enter zcash address of the party you want to swas with: ");
    loop {
        addr_fulfiller_zec = readline_and_trim();
        match bitcoin_zcash::util::address::Address::from_str(&addr_fulfiller_zec) {
            Ok(addr) => {
                match addr.network {
                    bitcoin_zcash::network::constants::Network::Bitcoin => {
                        println!("Only Testnet or Regtest currently supported! Exit.");
                        panic!("Only Testnet or Regtest.")
                    },
                    _ => {}
                }
                println!("Address {} accepted.\n", addr);
                blank.fulfiller.addr_zec = Some(addr);
                break
            }
            Err(_) => {
                println!("Error: invalid zcash address. Try again:");
                continue
            }
        }
    }

    println!(r#"Which currency would you like to swas out of ('btc' or 'zec'): "#);
    'direction: loop {
        let input = readline_and_trim();
        trade_direction = match input.as_ref() {
            "btc" => {
                print!("\nHow much bitcoin do you want to sell? ");
                let amount_sell: f64;
                'amount_1: loop {
                    let amount = readline_and_trim();
                    amount_sell = match amount.parse::<f64>() {
                        Ok(amount) => {
                            if amount < 0.000_010 {
                                println!("Its a dust. I need MORE!");
                                continue 'amount_1;
                            }
                            println!("Accepted: you want to sell {} btc.", amount);
                            amount
                        },
                        Err(..) => {
                            print!("Invalid amount. Try again: ");
                            continue 'amount_1;
                        },
                    };
                    io::stdout().flush().unwrap();
                    break 'amount_1;
                }

                print!("\nHow much zcash do you want to receive in exchange? ");
                let amount_buy: f64;
                'amount_2: loop {
                    let amount = readline_and_trim();
                    amount_buy = match amount.parse::<f64>() {
                        Ok(amount) => {
                            if amount < 0.000_010 {
                                println!("Its a dust. I need MORE!");
                                continue 'amount_2;
                            }
                            println!("Accepted: you want to receive {} zec.", amount);
                            amount
                        },
                        Err(..) => {
                            print!("Invalid amount. Try again: ");
                            continue 'amount_2;
                        },
                    };
                    break 'amount_2;
                }

                let current_blockcount_zec = match rpc_zec.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(err) => panic!("rpc_zec.getblockcount(): {}", err)
                };

                let current_blockcount_btc = match rpc_btc.getblockcount() {
                    Ok(blockcount) => blockcount,
                    Err(err) => panic!("rpc_btc.getblockcount(): {}", err)
                };
                let locktime_buy = match trade_direction {
                    TradeBlankParameters::BtcToZec(_) => current_blockcount_zec + LOCKTIME_BUY,
                    TradeBlankParameters::ZecToBtc(_) => current_blockcount_btc + LOCKTIME_BUY
                };
                let locktime_sell = match trade_direction {
                    TradeBlankParameters::BtcToZec(_) => current_blockcount_btc + LOCKTIME_SELL,
                    TradeBlankParameters::ZecToBtc(_) => current_blockcount_zec + LOCKTIME_SELL
                };
                let mut sell = TradeBlankCurParams {
                    amount: Some(amount_sell),
                    locktime: Some(locktime_sell),
                    max_fee: Some(1000),
                    confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
                };
                let mut buy = TradeBlankCurParams {
                    amount: Some(amount_buy),
                    locktime: Some(locktime_buy),
                    max_fee: Some(1000),
                    confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
                };
                TradeBlankParameters::BtcToZec(
                                    TradeBlankParams {
                                        buy: Some(buy),
                                        sell: Some(sell)
                                    })
            },
            "zec" => {
                print!("\nHow much zcash do you want to sell? ");
                let amount_sell: f64;
                'amount_3: loop {
                    let amount = readline_and_trim();
                    amount_sell = match amount.parse::<f64>() {
                        Ok(amount) => {
                            if amount < 0.000_010 {
                                println!("Its a dust. I need MORE!");
                                continue 'amount_3;
                            }
                            println!("Accepted: you want to sell {} zec.", amount);
                            amount
                        },
                        Err(..) => {
                            print!("Invalid amount. Try again: ");
                            continue 'amount_3;
                        },
                    };
                    io::stdout().flush().unwrap();
                    break 'amount_3;
                }

                print!("\nHow much bitcoin do you want to receive in exchange? ");
                let amount_buy: f64;
                'amount_4: loop {
                    let amount = readline_and_trim();
                    amount_buy = match amount.parse::<f64>() {
                        Ok(amount) => {
                            if amount < 0.000_010 {
                                println!("Its a dust. I need MORE!");
                                continue 'amount_4;
                            }
                            println!("Accepted: you want to receive {} btc.", amount);
                            amount
                        },
                        Err(..) => {
                            print!("Invalid amount. Try again: ");
                            continue 'amount_4;
                        },
                    };
                    break 'amount_4;
                }

                let mut sell = TradeBlankCurParams {
                    amount: Some(amount_sell),
                    locktime: Some(30),
                    max_fee: Some(1000),
                    confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
                };
                let mut buy = TradeBlankCurParams {
                    amount: Some(amount_buy),
                    locktime: Some(30),
                    max_fee: Some(1000),
                    confirmation_height: Some(config.minconfirmaions.unwrap_or(CONFIRMATIONS_MIN))
                };
                TradeBlankParameters::ZecToBtc(
                                    TradeBlankParams {
                                        buy: Some(buy),
                                        sell: Some(sell)
                                    })
            },
            _ => {
                println!("Invalid currency. Please enter again:");
                continue 'direction;
            }
        };
        break 'direction;
    }
    blank.id = trade_id;
    blank.params = Some(trade_direction);
    blank
}

fn get_rpcs(config: &Config) -> (RpcClient, RpcClient) {
    let rpc_btc  = RpcClient::new(format!("http://127.0.0.1:{}/", config.btcrpcport.unwrap_or(18332)),
            config.btcrpcuser.clone(),
            config.btcrpcpassword.clone());
    let rpc_zec  =  RpcClient::new(format!("http://127.0.0.1:{}/", config.zecrpcport.unwrap_or(18232)),
            config.zecrpcuser.clone(),
            config.zecrpcpassword.clone());
    (rpc_btc, rpc_zec)
}

fn get_new_addr_btc(rpc_btc: &RpcClient, account: &str) -> String {
    let addr = match rpc_btc.getnewaddress_legacy(account) {
        Ok(answer) => answer,
        Err(err) => panic!("rpc_btc.getnewaddress_legacy(account): {}", err)
    };
    println!("new btc addr: {}", addr);
    addr
}

fn get_new_addr_zec(rpc_zec: &RpcClient) -> String {
    let addr = match rpc_zec.getnewaddress("") {
        Ok(answer) => answer,
        Err(err) => panic!("rpc_zec.getnewaddres(\"\"): {}", err)
    };
    println!("new zec addr: {}", addr);
    addr
}
