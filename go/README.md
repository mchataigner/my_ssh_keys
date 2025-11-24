# fetch_ssh_keys (Go)

Fetch SSH public keys from common providers and print them in authorized_keys format.

## Installation

```bash
go build -o fetch_ssh_keys
```

Or install directly:

```bash
go install
```

## Usage

```bash
# Fetch from GitHub
./fetch_ssh_keys github torvalds

# Fetch from GitLab
./fetch_ssh_keys gitlab gitlab-org

# Read from local files
./fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub

# Read from stdin
echo "ssh-ed25519 AAAA... user@host" | ./fetch_ssh_keys stdin

# Write to a file
./fetch_ssh_keys github torvalds --output keys.txt

# Update authorized_keys file (with managed section)
./fetch_ssh_keys github torvalds --update

# Custom timeout
./fetch_ssh_keys github torvalds --timeout 30
```

## Options

- `--provider` - Provider to fetch keys from (github, gitlab, local, stdin). Default: github
- `-o, --output` - Write output to this file instead of stdout
- `-t, --timeout` - Network timeout in seconds when fetching from providers. Default: 10
- `--auth-file` - Path to the authorized_keys file to update when using --update. Default: ~/.ssh/authorized_keys
- `--update` - Update (replace or insert) the managed section inside an authorized_keys file

## Features

- Fetch public keys from GitHub's `/<user>.keys` endpoint
- Fetch public keys from GitLab's public API
- Read keys from local files (supports glob patterns)
- Read keys from stdin
- Validate SSH public key format
- Update authorized_keys file with managed sections
- Atomic file writes for safety
