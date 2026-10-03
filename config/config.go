package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Targets
	TargetURLs []string

	// Output
	OutputFile   string
	OutputFormat string

	// Performance
	Concurrency int
	Timeout     time.Duration
	Delay       time.Duration
	RetryCount  int

	// Behavior
	Verbose        bool
	Silent         bool
	NoColor        bool
	FollowRedirect bool
	ShowAll        bool
	ShowFailed     bool
	Insecure       bool // Skip TLS certificate verification

	// HTTP Settings
	UserAgent     string
	CustomHeaders map[string]string
	Methods       []string
	Cookie        string

	// Payloads
	OriginsFile string

	// Proxy (optional)
	ProxyURL string
}

func (c *Config) Validate() error {
	// Validate proxy URL if specified
	if c.ProxyURL != "" {
		if !strings.HasPrefix(c.ProxyURL, "http://") && !strings.HasPrefix(c.ProxyURL, "https://") && !strings.HasPrefix(c.ProxyURL, "socks5://") {
			return fmt.Errorf("invalid proxy URL protocol: %s", c.ProxyURL)
		}
	}
	// Validate targets
	if len(c.TargetURLs) == 0 {
		return fmt.Errorf("no targets specified")
	}

	// Validate concurrency
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}
	if c.Concurrency > 500 {
		return fmt.Errorf("concurrency cannot exceed 500")
	}

	// Validate timeout
	if c.Timeout < time.Second {
		return fmt.Errorf("timeout must be at least 1 second")
	}
	if c.Timeout > time.Minute*10 {
		return fmt.Errorf("timeout cannot exceed 10 minutes")
	}

	// Validate output format
	validFormats := map[string]bool{"json": true, "csv": true, "html": true, "txt": true}
	if !validFormats[strings.ToLower(c.OutputFormat)] {
		return fmt.Errorf("invalid output format: %s", c.OutputFormat)
	}

	// Validate methods
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true,
	}
	for _, method := range c.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	return nil
}

func LoadConfigFromFile(filepath string) (*Config, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Concurrency:    50,
		Timeout:        10 * time.Second,
		Delay:          0,
		RetryCount:     3,
		Verbose:        false,
		Silent:         false,
		NoColor:        false,
		FollowRedirect: false,
		UserAgent:      "OriginStrike/2.0 (Security Scanner)",
		Methods:        []string{"GET", "OPTIONS", "POST"},
		OutputFormat:   "json",
		CustomHeaders:  make(map[string]string),
	}
}
