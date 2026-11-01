package utils

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// ParseTargets parses targets from various input formats
func ParseTargets(inputs []string) ([]string, error) {
	var targets []string

	for _, input := range inputs {
		// Check if it's a file
		if IsFile(input) {
			fileTargets, err := ParseFromFile(input)
			if err != nil {
				return nil, fmt.Errorf("error reading file %s: %w", input, err)
			}
			targets = append(targets, fileTargets...)
		} else {
			// Single URL or domain
			normalized, err := NormalizeTarget(input)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %s: %w", input, err)
			}
			targets = append(targets, normalized)
		}
	}

	// Deduplicate
	targets = Deduplicate(targets)

	return targets, nil
}

func NormalizeTarget(input string) (string, error) {
	input = strings.TrimSpace(input)

	// Add scheme if missing (case-insensitive check)
	inputLower := strings.ToLower(input)
	if !strings.HasPrefix(inputLower, "http://") && !strings.HasPrefix(inputLower, "https://") {
		// Default to HTTPS
		input = "https://" + input
	}

	// Parse URL
	u, err := url.Parse(input)
	if err != nil {
		return "", err
	}

	// Validate host
	if u.Hostname() == "" {
		return "", fmt.Errorf("invalid hostname in %s", input)
	}

	// Normalize
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Remove trailing slash
	u.Path = strings.TrimRight(u.Path, "/")

	// Clear fragment and query for base URL
	u.Fragment = ""

	return u.String(), nil
}

func ParseFromFile(filepath string) ([]string, error) {
	var r io.Reader = os.Stdin
	if filepath != "-" {
		file, err := os.Open(filepath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		r = file
	}

	var targets []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		normalized, err := NormalizeTarget(line)
		if err != nil {
			continue // Skip invalid entries
		}

		targets = append(targets, normalized)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func IsFile(path string) bool {
	if path == "-" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func Deduplicate(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		normalized, err := NormalizeTarget(item)
		if err != nil {
			normalized = strings.ToLower(strings.TrimRight(item, "/"))
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, item)
		}
	}

	return result
}

// ExtractDomain extracts domain from URL
func ExtractDomain(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	return u.Hostname(), nil
}

// GenerateID generates unique ID for results
func GenerateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
