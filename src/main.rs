use std::process;
use std::path;
use std::str;
use std::io::Read;

use colored::Colorize;
use clap::{Parser, Subcommand, Args};

use serde::{Serialize, Deserialize};
use serde_json;
use base64::{Engine, engine::general_purpose};

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
const DEFAULT_STORE: &str = ".pvs/store.db";
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
  #[clap(name="set", about="Store a record in the database")]
  Store(StoreOptions),
  #[clap(name="get", about="Retrieve a record from the database")]
  Fetch(FetchOptions),
  #[clap(name="ls", about="List records in the database")]
  List(ListOptions),
}

#[derive(Args, Debug)]
struct StoreOptions {
  #[clap(help="The key to store the record under")]
  key: String,
}

#[derive(Args, Debug)]
struct FetchOptions {
  #[clap(long, help="Display the record's internal representation")]
  raw: bool,
  #[clap(help="The key to fetch the record from")]
  key: String,
}

#[derive(Args, Debug)]
struct ListOptions {
  #[clap(long, help="Display the records' internal representation")]
  raw: bool,
}

struct Context {
	_meta: sled::Tree,
	data: sled::Tree,
	cipher: ChaCha20Poly1305,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
	nonce: String,
	key:   String,
	val:   String,
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

	let mut entry = keyring::Entry::new_with_target(KEYRING_TARGET, "pvs.brianwolter.com", &store.display().to_string())?;
  let (_, key) = match entry.get_password() {
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
		_meta: meta,
		data: data,
		cipher: cipher,
	};

  match &opts.command {
  	Command::Store(sub) => store_record(&opts, sub, cxt),
    Command::Fetch(sub) => fetch_record(&opts, sub, cxt),
    Command::List(sub)  => list_records(&opts, sub, cxt),
  }?;

	db.flush()?;
  Ok(())
}

fn store_record(opts: &Options, sub: &StoreOptions, cxt: Context) -> Result<(), error::Error> {
	let key = hash_key(&sub.key);
	let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

  let stdin = std::io::stdin();
  let mut raw =  Vec::new();
  let mut handle = stdin.lock();
  handle.read_to_end(&mut raw)?;

	let env = wrap(&cxt, &sub.key, &raw)?;
	if opts.debug {
		println!(">>> {}", &env);
	}

	cxt.data.insert(key, env.as_bytes())?;
	Ok(())
}

fn fetch_record(opts: &Options, sub: &FetchOptions, cxt: Context) -> Result<(), error::Error> {
	let key = hash_key(&sub.key);
	let raw = match cxt.data.get(key)? {
		Some(raw) => raw,
		None => return Err(error::Error::NotFound),
	};
	if opts.debug {
		println!("<<< {}", str::from_utf8(&raw)?);
	}

	let (deckey, decval) = unwrap(&cxt, raw.as_ref())?;
	if opts.verbose {
		println!("{}\n-\n{}", &deckey, str::from_utf8(&decval)?);
	}else{
		println!("{}", str::from_utf8(&decval)?);
	}
	Ok(())
}

fn list_records(opts: &Options, sub: &ListOptions, cxt: Context) -> Result<(), error::Error> {
	let mut iter = cxt.data.iter();
	let mut i = 0;
	loop {
		if opts.verbose && i > 0 {
			println!();
		}

		let (key, val) = match iter.next() {
			Some(res) => res?,
			None => return Ok(()),
		};
		if opts.debug {
			println!("<<< {}: {}", str::from_utf8(&key)?, str::from_utf8(&val)?);
		}

		let (deckey, decval) = match unwrap(&cxt, val.as_ref()) {
			Ok((deckey, decval)) => (deckey, decval),
			Err(err) => {
				println!("* * * invalid record");
				continue;
			},
		};

		if opts.verbose {
			println!("{}\n-\n{}\n.", &deckey, str::from_utf8(&decval)?);
		}else{
			println!("{}", &deckey);
		}

		i += 1;
	}
}

fn default_store() -> Result<path::PathBuf, error::Error> {
	let mut home = match dirs::home_dir() {
		Some(home) => home,
		None => return Err(error::Error::NoSuchDirectory),
	};
	home.push(DEFAULT_STORE);
	Ok(home)
}

fn wrap(cxt: &Context, key: &str, val: &[u8]) -> Result<String, error::Error> {
	let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

	let key = key.to_string();
	let enckey = cxt.cipher.encrypt(&nonce, key.as_bytes())?;
	let encval = cxt.cipher.encrypt(&nonce, val)?;

	Ok(serde_json::to_string(&Envelope{
		nonce: general_purpose::STANDARD.encode(&nonce),
		key: general_purpose::STANDARD.encode(enckey),
		val: general_purpose::STANDARD.encode(encval),
	})?)
}

fn unwrap(cxt: &Context, data: &[u8]) -> Result<(String, Vec<u8>), error::Error> {
	let env: Envelope = serde_json::from_slice(data)?;
	let nonce: &[u8] = &general_purpose::STANDARD.decode(&env.nonce)?;

	let deckey = general_purpose::STANDARD.decode(&env.key)?; 
	let plnkey = cxt.cipher.decrypt(nonce.into(), deckey.as_ref())?;

	let decval = general_purpose::STANDARD.decode(&env.val)?; 
	let plnval = cxt.cipher.decrypt(nonce.into(), decval.as_ref())?;
	
	Ok((String::from_utf8(plnkey)?, plnval))
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
