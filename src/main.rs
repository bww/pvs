use std::process;

use clap::Parser;
use colored::Colorize;
use keyring;
use rpassword;

mod error;

const KEYRING_TARGET: &str = "User";

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
  #[clap(long, help="Enable debugging mode")]
  pub debug: bool,
  #[clap(long, help="Enable verbose output")]
  pub verbose: bool,
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
	let mut entry = keyring::Entry::new_with_target(KEYRING_TARGET, "coolvs.brianwolter.com", "*")?;
  let passwd = match entry.get_password() {
    Ok(passwd) => passwd,
    Err(err) => match err {
      keyring::Error::NoEntry => set_password(&mut entry)?,
      _ => return Err(err.into()),
    },
  };
  println!(">>> {:?}", passwd);
  Ok(())
}

fn set_password(entry: &mut keyring::Entry) -> Result<String, error::Error> {
  let pass = rpassword::prompt_password("New password for store: ")?;
  if pass != rpassword::prompt_password("   That password again: ")? {
    return Err(error::Error::PasswordMismatch);
  }
  entry.set_password(&pass)?;
  Ok(pass)
}
