/*!
fetch_ssh_keys

Fetch SSH public keys from common providers and print them in authorized_keys format.

Usage examples:
  fetch_ssh_keys github torvalds
  fetch_ssh_keys gitlab gitlab-org
  fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub
  echo "ssh-ed25519 AAAA... user@host" | fetch_ssh_keys stdin
*/

use clap::Parser;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = "fetch-ssh-keys/1.0";
const SECTION_NAME: &str = "managed";

#[derive(Parser, Debug)]
#[command(name = "fetch_ssh_keys")]
#[command(about = "Fetch SSH public keys and print in authorized_keys format", long_about = None)]
struct Args {
    /// Target username for github/gitlab, or file paths for local. 'stdin' reads from STDIN.
    #[arg(value_name = "TARGET")]
    target: Vec<String>,

    /// Provider to fetch keys from
    #[cfg_attr(feature = "gitlab", arg(long, value_parser = ["github", "gitlab", "local", "stdin"], default_value = "github"))]
    #[cfg_attr(not(feature = "gitlab"), arg(long, value_parser = ["github", "local", "stdin"], default_value = "github"))]
    provider: String,

    /// Write output to this file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Network timeout in seconds when fetching from providers
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Path to the authorized_keys file to update when using --update
    #[arg(long, default_value = "~/.ssh/authorized_keys")]
    auth_file: String,

    /// Update (replace or insert) the managed section inside an authorized_keys file
    #[arg(long)]
    update: bool,
}

/// Check if a line is a valid SSH public key
fn is_valid_pubkey(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }
    
    // Check key type
    let valid_types = ["ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", 
                       "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
                       "sk-ecdsa-sha2-nistp256@openssh.com"];
    if !valid_types.iter().any(|&t| parts[0] == t) && !parts[0].starts_with("ssh-") {
        return false;
    }
    
    // Check key body is base64-like
    let key_body = parts[1];
    key_body.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Fetch content from a URL
fn fetch_url(url: &str, timeout: Duration) -> Result<String, Box<dyn std::error::Error>> {
    let response = ureq::get(url)
        .timeout(timeout)
        .set("User-Agent", USER_AGENT)
        .call()?;
    
    if response.status() != 200 {
        return Err(format!("HTTP error {} when fetching {}", response.status(), url).into());
    }
    
    Ok(response.into_string()?)
}

/// Fetch public keys from GitHub's /<user>.keys endpoint
fn fetch_github(username: &str, timeout: Duration) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!("https://github.com/{}.keys", username);
    let data = fetch_url(&url, timeout)?;
    
    let keys: Vec<String> = data
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && is_valid_pubkey(l))
        .map(|l| l.to_string())
        .collect();
    
    Ok(keys)
}

#[cfg(feature = "gitlab")]
/// Fetch public keys from GitLab's public API
fn fetch_gitlab(username: &str, timeout: Duration) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Step 1: Search for user
    let search_url = format!("https://gitlab.com/api/v4/users?username={}", username);
    let data = fetch_url(&search_url, timeout)?;
    
    let users: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    
    if users.is_empty() {
        return Err(format!("GitLab: user '{}' not found", username).into());
    }
    
    let user_id = users[0]["id"]
        .as_u64()
        .ok_or("GitLab: couldn't determine user id")?;
    
    // Step 2: Fetch user's keys
    let keys_url = format!("https://gitlab.com/api/v4/users/{}/keys", user_id);
    let data = fetch_url(&keys_url, timeout)?;
    
    let keys_json: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    
    let mut keys = Vec::new();
    for k in keys_json {
        if let Some(key_str) = k["key"].as_str() {
            if is_valid_pubkey(key_str) {
                keys.push(key_str.trim().to_string());
            }
        }
    }
    
    Ok(keys)
}

/// Read SSH keys from local files
fn read_local(paths: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();
    
    for path in paths {
        let expanded_path = shellexpand::tilde(path).to_string();
        
        // Try glob expansion
        let mut matched = false;
        for entry in glob::glob(&expanded_path)? {
            matched = true;
            if let Ok(path) = entry {
                keys.extend(read_path(&path)?);
            }
        }
        
        // If no glob matches, try as literal path
        if !matched {
            let p = PathBuf::from(expanded_path);
            if p.exists() {
                keys.extend(read_path(&p)?);
            } else {
                // Try as directory with *.pub
                if p.is_dir() {
                    let pub_pattern = p.join("*.pub");
                    for entry in glob::glob(pub_pattern.to_str().unwrap())? {
                        if let Ok(path) = entry {
                            keys.extend(read_path(&path)?);
                        }
                    }
                }
            }
        }
    }
    
    // Filter valid keys
    let valid_keys: Vec<String> = keys
        .iter()
        .map(|k| k.trim())
        .filter(|k| !k.is_empty() && is_valid_pubkey(k))
        .map(|k| k.to_string())
        .collect();
    
    Ok(valid_keys)
}

/// Read lines from a path (file or directory)
fn read_path(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();
    
    if path.is_dir() {
        // Read *.pub files inside
        let pub_pattern = path.join("*.pub");
        for entry in glob::glob(pub_pattern.to_str().unwrap())? {
            if let Ok(file_path) = entry {
                keys.extend(read_file_lines(&file_path)?);
            }
        }
    } else if path.is_file() {
        keys.extend(read_file_lines(path)?);
    }
    
    Ok(keys)
}

/// Read lines from a file
fn read_file_lines(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    Ok(content.lines().map(|l| l.to_string()).collect())
}

/// Read keys from stdin
fn read_stdin() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    
    let keys: Vec<String> = buffer
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && is_valid_pubkey(l))
        .map(|l| l.to_string())
        .collect();
    
    Ok(keys)
}

/// Format keys for authorized_keys output
fn format_for_authorized_keys(lines: Vec<String>) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Update or insert a named section in an authorized_keys file
fn update_authorized_keys_section(
    path: &str,
    section_name: &str,
    key_lines: Vec<String>,
    source: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expanded_path = shellexpand::tilde(path).to_string();
    let path = Path::new(&expanded_path);
    
    let start_marker = format!("# BEGIN fetch_ssh_keys:{}", section_name);
    let end_marker = format!("# END fetch_ssh_keys:{}", section_name);
    
    // Read original file
    let orig_lines = if path.exists() {
        read_file_lines(path)?
    } else {
        Vec::new()
    };
    
    // Build new section
    let mut new_section = vec![start_marker.clone()];
    if let Some(src) = source {
        new_section.push(format!("# source: {}", src));
    }
    for line in &key_lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            new_section.push(trimmed.to_string());
        }
    }
    new_section.push(end_marker.clone());
    
    // Process original lines
    let mut out_lines = Vec::new();
    let mut i = 0;
    let mut replaced = false;
    let n = orig_lines.len();
    
    while i < n {
        let line = &orig_lines[i];
        if line.trim() == start_marker {
            // Found existing section - replace it
            replaced = true;
            out_lines.extend(new_section.clone());
            
            // Skip until end marker
            i += 1;
            while i < n && orig_lines[i].trim() != end_marker {
                i += 1;
            }
            if i < n && orig_lines[i].trim() == end_marker {
                i += 1;
            }
        } else {
            out_lines.push(line.clone());
            i += 1;
        }
    }
    
    // If section wasn't found, append it
    if !replaced {
        if !out_lines.is_empty() && !out_lines.last().unwrap().trim().is_empty() {
            out_lines.push(String::new());
        }
        out_lines.extend(new_section);
    }
    
    // Write atomically
    let tmp_path = format!("{}.tmp", expanded_path);
    
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut file = File::create(&tmp_path)?;
    for line in out_lines {
        writeln!(file, "{}", line)?;
    }
    file.sync_all()?;
    drop(file);
    
    fs::rename(&tmp_path, path)?;
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();
    
    // If provider is specified as first positional argument, shift it
    #[cfg(feature = "gitlab")]
    let providers = ["github", "gitlab", "local", "stdin"];
    #[cfg(not(feature = "gitlab"))]
    let providers = ["github", "local", "stdin"];
    if !args.target.is_empty() && providers.contains(&args.target[0].as_str()) {
        args.provider = args.target[0].clone();
        args.target = args.target[1..].to_vec();
    }
    
    // Check for conflicts
    if args.output.is_some() && args.update {
        eprintln!("--output and --update are mutually exclusive");
        std::process::exit(1);
    }
    
    let timeout = Duration::from_secs(args.timeout);
    let mut keys = Vec::new();
    let mut source_desc: Option<String> = None;
    
    match args.provider.as_str() {
        "github" => {
            if args.target.is_empty() {
                eprintln!("GitHub provider requires a username");
                std::process::exit(1);
            }
            let username = &args.target[0];
            match fetch_github(username, timeout) {
                Ok(k) => {
                    keys = k;
                    source_desc = Some(format!("github:{}", username));
                }
                Err(e) => {
                    eprintln!("Warning: failed to fetch from github:{}: {}", username, e);
                }
            }
        }
        #[cfg(feature = "gitlab")]
        "gitlab" => {
            if args.target.is_empty() {
                eprintln!("GitLab provider requires a username");
                std::process::exit(1);
            }
            let username = &args.target[0];
            match fetch_gitlab(username, timeout) {
                Ok(k) => {
                    keys = k;
                    source_desc = Some(format!("gitlab:{}", username));
                }
                Err(e) => {
                    eprintln!("Warning: failed to fetch from gitlab:{}: {}", username, e);
                }
            }
        }
        "local" => {
            if args.target.is_empty() {
                eprintln!("local provider requires at least one file path or directory");
                std::process::exit(1);
            }
            keys = read_local(&args.target)?;
            source_desc = Some("local".to_string());
        }
        "stdin" => {
            keys = read_stdin()?;
            source_desc = Some("stdin".to_string());
        }
        _ => {
            eprintln!("Unknown provider: {}", args.provider);
            std::process::exit(1);
        }
    }
    
    if keys.is_empty() {
        eprintln!("# No valid SSH public keys found.");
    }
    
    let out_lines = format_for_authorized_keys(keys);
    
    if let Some(output_path) = args.output {
        let mut file = File::create(output_path)?;
        for line in out_lines {
            writeln!(file, "{}", line)?;
        }
    } else if args.update {
        update_authorized_keys_section(
            &args.auth_file,
            SECTION_NAME,
            out_lines,
            source_desc.as_deref(),
        )?;
    } else {
        for line in out_lines {
            println!("{}", line);
        }
    }
    
    Ok(())
}
