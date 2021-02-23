//! Cosigning server error module

use std::{error, fmt};

/// An error enum for revault_net functionality
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Error when cosigning server is requested to sign an input that has
    /// already been signed.
    SignOnlyOnce(String),
    /// Error while creating a signature for an input in a spend transaction
    SignatureCreation(String),
    /// Database Error
    Database(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SignOnlyOnce(ref e) => write!(f, "Sign Only Once Error: {}", e),
            Error::SugnatureCreation(ref e) => write!(f, "Signature Creation Error: {}", e),
            Error::Database(ref e) => write!(f, "Database Error: {}", e),
        }
    }
}

impl error::Error for Error {}
