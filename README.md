# PVS
_PVS_ is an ecrypted key/value store with a command line interface. It is intended to be useful for storing a relatively small amount of possibly-sensitive information that can be accessed by scripts.

## Installing
You can build and install PVS from source as follows:

```
$ cd pvs && cargo install
```

## Usage
PVS has three main operations: store, fetch, and list.

In all cases the record is encrypted using a key that is stored in your platform's standard secret manager. On first run you will be prompted to create the password that this key is derived from. On subsequent runs you will not be prompted for your password because PVS will fetch it from the secret management service.

On MacOS, your password is stored in Keychain. On Linux, it may be KDE Wallet or GNOME Keyring, depending on your setup. On Windows? Who knows, I haven't tested it on Windows. The [Keyring](https://docs.rs/keyring/latest/keyring/) crate is used for interacting with the underlying secret storage service.

### Store a record in the database
```
$ echo "Store this secret data" | pvs set example.1
```

### List records in the database
```
$ pvs ls
example.1
```

### Fetch a record from the database
```
$ pvs get example.1
Store this secret data
```

## Getting help
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
