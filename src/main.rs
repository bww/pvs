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
	let entry = keyring::Entry::new_with_target(KEYRING_TARGET, "coolvs.brianwolter.com", "*")?;
  let passwd = match entry.get_password() {
    Ok(passwd) => passwd,
    Err(err) => match err {
      keyring::Error::NoEntry => read_password()?,
      _ => return Err(err.into()),
    },
  };
  println!(">>> {:?}", passwd);
  Ok(())
}

fn read_password() -> Result<String, error::Error> {
  let pass = rpassword::prompt_password("Password: ")?;
  if pass != rpassword::prompt_password("Again: ")? {
    Err(error::Error::PasswordMismatch)
  }else{
    Ok(pass)
  }
}
