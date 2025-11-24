# fetch_ssh_keys (Rust)

Fetch SSH public keys from common providers and print them in authorized_keys format.

This is a Rust port of the Python `fetch_ssh_keys` utility with identical functionality.

## Features

- Fetch SSH public keys from GitHub users
- Fetch SSH public keys from GitLab users
- Read SSH public keys from local files (with glob support)
- Read SSH public keys from stdin
- Update authorized_keys file with managed sections
- Validate SSH key format
- Zero external dependencies for core functionality

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/fetch_ssh_keys`.

## Usage

### Fetch from GitHub
```bash
fetch_ssh_keys github torvalds
# or simply
fetch_ssh_keys torvalds
```

### Fetch from GitLab
```bash
fetch_ssh_keys gitlab gitlab-org
```

### Read from local files
```bash
fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub
# Supports glob patterns
fetch_ssh_keys local ~/.ssh/*.pub
```

### Read from stdin
```bash
echo "ssh-ed25519 AAAA... user@host" | fetch_ssh_keys stdin
```

### Write to file
```bash
fetch_ssh_keys github torvalds -o authorized_keys
```

### Update authorized_keys file
```bash
fetch_ssh_keys github torvalds --update
```

This will create or update a managed section in `~/.ssh/authorized_keys`:
```
# BEGIN fetch_ssh_keys:managed
# source: github:torvalds
ssh-rsa AAAA...
# END fetch_ssh_keys:managed
```

## Command Line Options

```
Options:
      --provider <PROVIDER>
          Provider to fetch keys from
          [default: github]
          [possible values: github, gitlab, local, stdin]

  -o, --output <OUTPUT>
          Write output to this file instead of stdout

  -t, --timeout <TIMEOUT>
          Network timeout in seconds when fetching from providers
          [default: 10]

      --auth-file <AUTH_FILE>
          Path to the authorized_keys file to update when using --update
          [default: ~/.ssh/authorized_keys]

      --update
          Update (replace or insert) the managed section inside an authorized_keys file

  -h, --help
          Print help
```

## Comparison with Python version

This Rust implementation provides:
- ✅ Same functionality as Python version
- ✅ Better performance (compiled binary)
- ✅ Static binary (no Python runtime required)
- ✅ Memory safety guarantees
- ✅ Compatible command-line interface

## License

See `../LICENSE` for license information.
