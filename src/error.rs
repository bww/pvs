use std::io;
use std::fmt;
use std::str;

use keyring;
use argon2;
use chacha20poly1305;
use crypto_common;
use serde_json;
use sled;

#[derive(Debug)]
pub enum Error {
  IOError(io::Error),
  Utf8Error(str::Utf8Error),
  SerdeError(serde_json::Error),
  SledError(sled::Error),
  KeyringError(keyring::Error),
  Argon2Error(argon2::Error),
  DeriveKeyError(argon2::password_hash::Error),
  InvalidLength(crypto_common::InvalidLength),
  CipherError(chacha20poly1305::Error),
  InvalidPassword,
	VersionMismatch,
  PasswordMismatch,
  PasswordEmpty,
  NoSuchDirectory,
  NotFound,
}

impl From<str::Utf8Error> for Error {
  fn from(err: str::Utf8Error) -> Self {
    Self::Utf8Error(err)
  }
}

impl From<io::Error> for Error {
  fn from(err: io::Error) -> Self {
    Self::IOError(err)
  }
}

impl From<serde_json::Error> for Error {
  fn from(err: serde_json::Error) -> Self {
		Self::SerdeError(err)
  }
}

impl From<sled::Error> for Error {
  fn from(err: sled::Error) -> Self {
    Self::SledError(err)
  }
}

impl From<keyring::Error> for Error {
  fn from(err: keyring::Error) -> Self {
    Self::KeyringError(err)
  }
}

impl From<argon2::Error> for Error {
  fn from(err: argon2::Error) -> Self {
    Self::Argon2Error(err)
  }
}

impl From<argon2::password_hash::Error> for Error {
  fn from(err: argon2::password_hash::Error) -> Self {
    Self::DeriveKeyError(err)
  }
}

impl From<crypto_common::InvalidLength> for Error {
  fn from(err: crypto_common::InvalidLength) -> Self {
    Self::InvalidLength(err)
  }
}

impl From<chacha20poly1305::Error> for Error {
  fn from(err: chacha20poly1305::Error) -> Self {
		Self::CipherError(err)
  }
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::IOError(err) => err.fmt(f),
      Self::Utf8Error(err) => err.fmt(f),
      Self::SerdeError(err) => err.fmt(f),
      Self::SledError(err) => err.fmt(f),
      Self::KeyringError(err) => err.fmt(f),
      Self::Argon2Error(err) => err.fmt(f),
      Self::DeriveKeyError(err) => err.fmt(f),
      Self::InvalidLength(err) => err.fmt(f),
      Self::CipherError(err) => err.fmt(f),
      Self::InvalidPassword => write!(f, "Invalid password"),
      Self::VersionMismatch => write!(f, "Version mismatch"),
      Self::PasswordMismatch => write!(f, "Passwords do not match"),
      Self::PasswordEmpty => write!(f, "Password is empty"),
      Self::NoSuchDirectory => write!(f, "No such directory"),
      Self::NotFound => write!(f, "Not found"),
    }
  }
}
