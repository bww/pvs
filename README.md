# PVS
_PVS_ is an ecrypted key/value store with a command line interface. It is intended to be useful for storing a relatively small amount of possibly-sensitive information that can be accessed by scripts.

## Installing
You can build and install PVS from source as follows:

```
$ cd pvs && cargo install
```

## Usage
PVS has three main operations:

* Store a record in the database,
* List records in the database,
* Fetch a record from the database.

In all cases the record is encrypted (possibly transparently) using a key that is stored in your platform's standard secret manager. On MacOS, this is Keychain. On Linux, it may be KDE Wallet or GNOME Keyring, depending on your setup. On Windows? Who knows, I haven't tested it on Windows.

The [Keyring](https://docs.rs/keyring/latest/keyring/) crate is used for interacting with the underlying secret storage service.

Use `pvs` or `pvs help` for usage information.

```
$ pvs

USAGE:
    pvs [OPTIONS] <SUBCOMMAND>

OPTIONS:
        --debug            Enable debugging mode
    -h, --help             Print help information
        --store <STORE>    The key-value store to operate on
    -V, --version          Print version information
        --verbose          Enable verbose output

SUBCOMMANDS:
    get     Fetch and decrypt a record from the database
    help    Print this message or the help of the given subcommand(s)
    ls      Decrypt and list records in the database
    set     Encrypt and store a record in the database

```
