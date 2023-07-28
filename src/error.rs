use std::io;
use std::fmt;

use keyring;

#[derive(Debug)]
pub enum Error {
  IOError(io::Error),
  KeyringError(keyring::Error),
  PasswordMismatch,
  PasswordEmpty,
}

impl From<io::Error> for Error {
  fn from(err: io::Error) -> Self {
    Self::IOError(err)
  }
}

impl From<keyring::Error> for Error {
  fn from(err: keyring::Error) -> Self {
    Self::KeyringError(err)
  }
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::IOError(err) => err.fmt(f),
      Self::KeyringError(err) => err.fmt(f),
      Self::PasswordMismatch => write!(f, "Passwords do not match"),
      Self::PasswordEmpty => write!(f, "Password is empty"),
    }
  }
}
