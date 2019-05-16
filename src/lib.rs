//! # Rust Snark-Wallet Atomic Swap library
//!
//! This is a library for which supports the swaps across Bitcoin and Zcash
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!

extern crate failure;
#[macro_use] extern crate failure_derive;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate display_derive;
pub mod swas;
