// fetch_ssh_keys
//
// Fetch SSH public keys from common providers and print them in authorized_keys format.
//
// Usage examples:
//   fetch_ssh_keys github torvalds
//   fetch_ssh_keys gitlab gitlab-org
//   fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub
//   echo "ssh-ed25519 AAAA... user@host" | fetch_ssh_keys stdin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	userAgent   = "fetch-ssh-keys/1.0"
	sectionName = "managed"
)

var (
	sshKeyRegex = regexp.MustCompile(`^(?P<type>ssh-[a-z0-9-]+|ecdsa-sha2-nistp\d+)\s+(?P<body>[A-Za-z0-9+/=]+)(\s+(?P<comment>.*))?$`)
)

// isValidPubkey checks if a line is a valid SSH public key
func isValidPubkey(line string) bool {
	return sshKeyRegex.MatchString(strings.TrimSpace(line))
}

// fetchURL fetches content from a URL with timeout
func fetchURL(url string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error %d when fetching %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// fetchGithub fetches public keys from GitHub's /<user>.keys endpoint
func fetchGithub(username string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	data, err := fetchURL(url, timeout)
	if err != nil {
		return nil, err
	}

	var keys []string
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && isValidPubkey(trimmed) {
			keys = append(keys, trimmed)
		}
	}

	return keys, nil
}

// GitLabUser represents a GitLab user from the API
type GitLabUser struct {
	ID int `json:"id"`
}

// GitLabKey represents a GitLab SSH key from the API
type GitLabKey struct {
	Key string `json:"key"`
}

// fetchGitlab fetches public keys from GitLab's public API
func fetchGitlab(username string, timeout time.Duration) ([]string, error) {
	// Step 1: Search for user
	searchURL := fmt.Sprintf("https://gitlab.com/api/v4/users?username=%s", username)
	data, err := fetchURL(searchURL, timeout)
	if err != nil {
		return nil, err
	}

	var users []GitLabUser
	if err := json.Unmarshal([]byte(data), &users); err != nil {
		return nil, fmt.Errorf("failed to decode GitLab user search response: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("GitLab: user '%s' not found", username)
	}

	userID := users[0].ID

	// Step 2: Fetch user's keys
	keysURL := fmt.Sprintf("https://gitlab.com/api/v4/users/%d/keys", userID)
	data, err = fetchURL(keysURL, timeout)
	if err != nil {
		return nil, err
	}

	var keysJSON []GitLabKey
	if err := json.Unmarshal([]byte(data), &keysJSON); err != nil {
		return nil, fmt.Errorf("failed to decode GitLab keys response: %w", err)
	}

	var keys []string
	for _, k := range keysJSON {
		trimmed := strings.TrimSpace(k.Key)
		if isValidPubkey(trimmed) {
			keys = append(keys, trimmed)
		}
	}

	return keys, nil
}

// readLocal reads SSH keys from local files
func readLocal(paths []string) ([]string, error) {
	var allKeys []string

	for _, path := range paths {
		// Expand tilde
		if strings.HasPrefix(path, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				path = filepath.Join(home, path[1:])
			}
		}

		// Try glob expansion
		matches, err := filepath.Glob(path)
		if err != nil {
			continue
		}

		if len(matches) == 0 {
			// No glob matches, try as literal path
			matches = []string{path}
		}

		for _, match := range matches {
			keys, err := readPath(match)
			if err != nil {
				continue
			}
			allKeys = append(allKeys, keys...)
		}
	}

	// Filter valid keys
	var validKeys []string
	for _, key := range allKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed != "" && isValidPubkey(trimmed) {
			validKeys = append(validKeys, trimmed)
		}
	}

	return validKeys, nil
}

// readPath reads lines from a path (file or directory)
func readPath(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var keys []string

	if info.IsDir() {
		// Read *.pub files inside
		pattern := filepath.Join(path, "*.pub")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			lines, err := readFileLines(match)
			if err != nil {
				continue
			}
			keys = append(keys, lines...)
		}
	} else {
		lines, err := readFileLines(path)
		if err != nil {
			return nil, err
		}
		keys = append(keys, lines...)
	}

	return keys, nil
}

// readFileLines reads lines from a file
func readFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// readStdin reads keys from stdin
func readStdin() ([]string, error) {
	var keys []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && isValidPubkey(line) {
			keys = append(keys, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

// formatForAuthorizedKeys formats keys for authorized_keys output
func formatForAuthorizedKeys(lines []string) []string {
	var formatted []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			formatted = append(formatted, trimmed)
		}
	}
	return formatted
}

// updateAuthorizedKeysSection updates or inserts a named section in an authorized_keys file
func updateAuthorizedKeysSection(path, sectionName string, keyLines []string, source string) error {
	// Expand tilde
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, path[1:])
	}

	startMarker := fmt.Sprintf("# BEGIN fetch_ssh_keys:%s", sectionName)
	endMarker := fmt.Sprintf("# END fetch_ssh_keys:%s", sectionName)

	// Read original file
	var origLines []string
	if _, err := os.Stat(path); err == nil {
		origLines, _ = readFileLines(path)
	}

	// Build new section
	newSection := []string{startMarker}
	if source != "" {
		newSection = append(newSection, fmt.Sprintf("# source: %s", source))
	}
	for _, line := range keyLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			newSection = append(newSection, trimmed)
		}
	}
	newSection = append(newSection, endMarker)

	// Process original lines
	var outLines []string
	replaced := false
	i := 0
	n := len(origLines)

	for i < n {
		line := origLines[i]
		if strings.TrimSpace(line) == startMarker {
			// Found existing section - replace it
			replaced = true
			outLines = append(outLines, newSection...)

			// Skip until end marker
			i++
			for i < n && strings.TrimSpace(origLines[i]) != endMarker {
				i++
			}
			if i < n && strings.TrimSpace(origLines[i]) == endMarker {
				i++
			}
		} else {
			outLines = append(outLines, line)
			i++
		}
	}

	// If section wasn't found, append it
	if !replaced {
		if len(outLines) > 0 && strings.TrimSpace(outLines[len(outLines)-1]) != "" {
			outLines = append(outLines, "")
		}
		outLines = append(outLines, newSection...)
	}

	// Write atomically
	tmpPath := path + ".tmp"

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	for _, line := range outLines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			file.Close()
			os.Remove(tmpPath)
			return err
		}
	}

	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}

func main() {
	var (
		provider string
		output   string
		timeout  int
		authFile string
		update   bool
	)

	pflag.StringVar(&provider, "provider", "github", "Provider to fetch keys from (github, gitlab, local, stdin)")
	pflag.StringVarP(&output, "output", "o", "", "Write output to this file instead of stdout")
	pflag.IntVarP(&timeout, "timeout", "t", 10, "Network timeout in seconds when fetching from providers")
	pflag.StringVar(&authFile, "auth-file", "~/.ssh/authorized_keys", "Path to the authorized_keys file to update when using --update")
	pflag.BoolVar(&update, "update", false, "Update (replace or insert) the managed section inside an authorized_keys file")

	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fetch_ssh_keys [OPTIONS] [TARGET...]\n\n")
		fmt.Fprintf(os.Stderr, "Fetch SSH public keys and print in authorized_keys format\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  fetch_ssh_keys github torvalds\n")
		fmt.Fprintf(os.Stderr, "  fetch_ssh_keys gitlab gitlab-org\n")
		fmt.Fprintf(os.Stderr, "  fetch_ssh_keys local ~/.ssh/id_rsa.pub ~/.ssh/another_key.pub\n")
		fmt.Fprintf(os.Stderr, "  echo \"ssh-ed25519 AAAA... user@host\" | fetch_ssh_keys stdin\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}

	pflag.Parse()
	targets := pflag.Args()

	// If provider is specified as first positional argument, shift it
	providers := []string{"github", "gitlab", "local", "stdin"}
	if len(targets) > 0 {
		for _, p := range providers {
			if targets[0] == p {
				provider = targets[0]
				targets = targets[1:]
				break
			}
		}
	}

	// Check for conflicts
	if output != "" && update {
		fmt.Fprintln(os.Stderr, "--output and --update are mutually exclusive")
		os.Exit(1)
	}

	timeoutDuration := time.Duration(timeout) * time.Second
	var keys []string
	var sourceDesc string
	var err error

	switch provider {
	case "github":
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "GitHub provider requires a username")
			os.Exit(1)
		}
		username := targets[0]
		keys, err = fetchGithub(username, timeoutDuration)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch from github:%s: %v\n", username, err)
		}
		sourceDesc = fmt.Sprintf("github:%s", username)

	case "gitlab":
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "GitLab provider requires a username")
			os.Exit(1)
		}
		username := targets[0]
		keys, err = fetchGitlab(username, timeoutDuration)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to fetch from gitlab:%s: %v\n", username, err)
		}
		sourceDesc = fmt.Sprintf("gitlab:%s", username)

	case "local":
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "local provider requires at least one file path or directory")
			os.Exit(1)
		}
		keys, err = readLocal(targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading local files: %v\n", err)
			os.Exit(2)
		}
		sourceDesc = "local"

	case "stdin":
		keys, err = readStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(2)
		}
		sourceDesc = "stdin"

	default:
		fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", provider)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "# No valid SSH public keys found.")
	}

	outLines := formatForAuthorizedKeys(keys)

	if output != "" {
		file, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(2)
		}
		defer file.Close()

		for _, line := range outLines {
			fmt.Fprintln(file, line)
		}
	} else if update {
		if err := updateAuthorizedKeysSection(authFile, sectionName, outLines, sourceDesc); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating authorized_keys file: %v\n", err)
			os.Exit(3)
		}
	} else {
		for _, line := range outLines {
			fmt.Println(line)
		}
	}
}
