use std::process;
use std::path;
use std::str;

use clap::Parser;
use colored::Colorize;

use sled;
use dirs;

use keyring;
use rpassword;
use chacha20poly1305::{self, ChaCha20Poly1305, KeyInit, AeadCore, aead::{Aead, OsRng}};
use argon2::{self, PasswordHasher};

mod error;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEYRING_TARGET: &str = "User";
const DEFAULT_STORE: &str = ".coolvs/store.db";
const KEYLEN: usize = 32;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
  #[clap(long, help="Enable debugging mode")]
  pub debug: bool,
  #[clap(long, help="Enable verbose output")]
  pub verbose: bool,
  #[clap(long, help="The key-value store to operate on")]
  pub store: Option<String>,
  #[clap(help="Command")]
  pub cmd: Option<String>,
}

fn main() {
  match cmd(){
    Ok(_)    => return,
    Err(err) => {
      eprintln!("{}", &format!("* * * {}", err).yellow().bold());
      process::exit(1);
    },
  };
}

fn cmd() -> Result<(), error::Error> {
  let opts = Options::parse();
  let store: path::PathBuf = match opts.store {
    Some(store) => path::PathBuf::from(&store),
    None => default_store()?,
  };

	let mut entry = keyring::Entry::new_with_target(KEYRING_TARGET, "coolvs.brianwolter.com", &store.display().to_string())?;
  let (passwd, key) = match entry.get_password() {
    Ok(passwd) => (passwd.clone(), derive_key(&passwd)?),
    Err(err) => match err {
      keyring::Error::NoEntry => collect_password(&store, &mut entry)?,
      _ => return Err(err.into()),
    },
  };

	let db = sled::open(store)?;
	let data = db.open_tree("data")?;
	let meta = db.open_tree("meta")?;

	match meta.get("version")? {
		Some(v) => if v != VERSION { return Err(error::Error::VersionMismatch) },
		None => { meta.insert("version", VERSION)?; },
	};

	let cipher = ChaCha20Poly1305::new_from_slice(&key)?;

	match opts.cmd {
		None => {},
		Some(cmd) => match cmd.as_ref() {
			"enc" => { store_message(cipher)?; },
			"dec" => { fetch_message(cipher)?; },
			_		  => return Err(error::Error::InvalidCommand),
		},
	};

  Ok(())
}

fn store_message(cipher: ChaCha20Poly1305) -> Result<(), error::Error> {
	let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
	let enc = cipher.encrypt(&nonce, "Cool, this is the message".as_ref())?;
	let dec = cipher.decrypt(&nonce, enc.as_ref())?;
	println!(">>> DEC DEC DEC {:?}", str::from_utf8(&dec)?);
	Ok(())
}

fn fetch_message(cipher: ChaCha20Poly1305) -> Result<String, error::Error> {
	Ok("Hi".to_string())
}

fn default_store() -> Result<path::PathBuf, error::Error> {
	let mut home = match dirs::home_dir() {
		Some(home) => home,
		None => return Err(error::Error::NoSuchDirectory),
	};
	home.push(DEFAULT_STORE);
	Ok(home)
}

fn derive_key(passwd: &str) -> Result<[u8; KEYLEN], error::Error> {
	let hash = argon2::password_hash::PasswordHash::new(&passwd)?;
	let passwd = match hash.hash {
		Some(passwd) => passwd,
		None => return Err(error::Error::InvalidPassword),
	};
	if passwd.len() < KEYLEN {
		return Err(error::Error::InvalidPassword) 
	}
	let mut key = [0u8; KEYLEN];
	let pwb = passwd.as_bytes();
	key[..KEYLEN].clone_from_slice(&pwb[..KEYLEN]);
	Ok(key)
}

fn collect_password<P: AsRef<path::Path>>(store: P, entry: &mut keyring::Entry) -> Result<(String, [u8; 32]), error::Error> {
  println!("[{}]", store.as_ref().to_string_lossy());

	let pass = rpassword::prompt_password("New password for store: ")?;
  if pass.len() == 0 {
    return Err(error::Error::PasswordEmpty);
  }
  if pass != rpassword::prompt_password("   That password again: ")? {
    return Err(error::Error::PasswordMismatch);
  }
	
	let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
	let passwd = argon2::Argon2::default().hash_password(pass.as_bytes(), &salt)?.to_string();
	let key = derive_key(&passwd)?;

  entry.set_password(&passwd)?;
  Ok((passwd, key))
}
