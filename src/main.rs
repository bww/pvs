use std::process;
use std::path;
use std::str;
use std::io::Read;

use colored::Colorize;
use clap::{Parser, Subcommand, Args};

use sled;
use dirs;

use keyring;
use rpassword;
use chacha20poly1305::{self, ChaCha20Poly1305, KeyInit, AeadCore, aead::{Aead, OsRng}};
use argon2::{self, PasswordHasher};
use sha2::Digest;

mod error;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEYRING_TARGET: &str = "User";
const DEFAULT_STORE: &str = ".coolvs/store.db";
const KEYLEN: usize = 32;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Options {
  #[clap(long, help="Enable debugging mode")]
  debug: bool,
  #[clap(long, help="Enable verbose output")]
  verbose: bool,
  #[clap(long, help="The key-value store to operate on")]
  store: Option<String>,
  #[clap(subcommand)]
  command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
  #[clap(about="Store a record in the database")]
  Store(StoreOptions),
  #[clap(about="Retrieve a record from the database")]
  Fetch(FetchOptions),
}

#[derive(Args, Debug)]
struct StoreOptions {
  #[clap(long, short='k', help="The key to store the record under")]
  key: String,
}

#[derive(Args, Debug)]
struct FetchOptions {
  #[clap(long, short='k', help="The key to fetch the record from")]
  key: String,
}

struct Context {
	meta: sled::Tree,
	data: sled::Tree,
	cipher: ChaCha20Poly1305,
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
  let store: path::PathBuf = match &opts.store {
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
	let cxt = Context{
		meta: meta,
		data: data,
		cipher: cipher,
	};

  match &opts.command {
  	Command::Store(sub) => store_record(&opts, sub, cxt),
    Command::Fetch(sub) => fetch_record(&opts, sub, cxt),
  }?;

  Ok(())
}

fn store_record(opts: &Options, sub: &StoreOptions, cxt: Context) -> Result<(), error::Error> {
	let hkey = hash_key(&sub.key);
	let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
	let enc = cxt.cipher.encrypt(&nonce, "Cool, this is the message".as_ref())?;

  let stdin = std::io::stdin();
  let mut val =  Vec::new();
  let mut handle = stdin.lock();
  handle.read_to_end(&mut val);
	
	println!(">>> KEY: {} -> {}", hkey, str::from_utf8(&val)?);
	Ok(())
}

fn fetch_record(opts: &Options, sub: &FetchOptions, cxt: Context) -> Result<(), error::Error> {
	//let dec = cipher.decrypt(&nonce, enc.as_ref())?;
	Ok(())
}

fn default_store() -> Result<path::PathBuf, error::Error> {
	let mut home = match dirs::home_dir() {
		Some(home) => home,
		None => return Err(error::Error::NoSuchDirectory),
	};
	home.push(DEFAULT_STORE);
	Ok(home)
}

fn hash_key(key: &str) -> String {
	format!("{:02x}", sha2::Sha512::digest(key.as_bytes()))
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
