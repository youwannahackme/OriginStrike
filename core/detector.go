package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/youwannahackme/originstrike/config"
)

type Detector struct {
	client            *http.Client
	config            *config.Config
	trustedPatterns   []string
	maliciousPatterns []string
	verificationCache map[string]bool
	cacheMutex        sync.RWMutex
}

func NewDetector(cfgs ...*config.Config) *Detector {
	var cfg *config.Config
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	timeout := 15 * time.Second
	insecure := true
	proxyFunc := http.ProxyFromEnvironment

	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.ProxyURL != "" {
			if parsedProxy, err := url.Parse(cfg.ProxyURL); err == nil {
				proxyFunc = http.ProxyURL(parsedProxy)
			}
		}
	}

	transport := &http.Transport{
		Proxy: proxyFunc,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
	}

	return &Detector{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if cfg != nil && cfg.FollowRedirect {
					return nil
				}
				return http.ErrUseLastResponse
			},
		},
		config:          cfg,
		trustedPatterns: []string{},
		maliciousPatterns: []string{
			`evil\.com`,
			`attacker\.com`,
			`malicious\.com`,
			`javascript:`,
			`data:text/html`,
		},
		verificationCache: make(map[string]bool),
	}
}

func (d *Detector) setDetectorHeaders(req *http.Request) {
	if d.config == nil {
		return
	}
	if d.config.Cookie != "" {
		req.Header.Set("Cookie", d.config.Cookie)
	}
	for k, v := range d.config.CustomHeaders {
		req.Header.Set(k, v)
	}
}

// VerifyVulnerability performs triple-checking to ensure zero false positives
func (d *Detector) VerifyVulnerability(result *ScanResult) bool {
	cacheKey := fmt.Sprintf("%s:%s:%s", result.URL, result.Origin, result.Method)

	// Check cache first
	d.cacheMutex.RLock()
	if cached, exists := d.verificationCache[cacheKey]; exists {
		d.cacheMutex.RUnlock()
		return cached
	}
	d.cacheMutex.RUnlock()

	// Verification 1: Re-test with same parameters
	verified1 := d.verifyWithRetries(result.URL, result.Origin, result.Method, 3)
	if !verified1 {
		d.cacheMutex.Lock()
		d.verificationCache[cacheKey] = false
		d.cacheMutex.Unlock()
		return false
	}

	// Verification 2: Test with slightly different User-Agent
	verified2 := d.verifyWithDifferentUA(result.URL, result.Origin, result.Method)
	if !verified2 {
		d.cacheMutex.Lock()
		d.verificationCache[cacheKey] = false
		d.cacheMutex.Unlock()
		return false
	}

	// Verification 3: Confirm response body actually differs (not just headers)
	verified3 := d.verifyResponseConsistency(result)
	if !verified3 {
		d.cacheMutex.Lock()
		d.verificationCache[cacheKey] = false
		d.cacheMutex.Unlock()
		return false
	}

	// All verifications passed
	d.cacheMutex.Lock()
	d.verificationCache[cacheKey] = true
	d.cacheMutex.Unlock()
	return true
}

func cleanHTTPMethod(method string) string {
	method = strings.TrimSpace(method)
	if idx := strings.Index(method, " "); idx != -1 {
		method = method[:idx]
	}
	if method == "" {
		return "GET"
	}
	return strings.ToUpper(method)
}

func (d *Detector) verifyWithRetries(targetURL, origin, method string, retries int) bool {
	cleanMethod := cleanHTTPMethod(method)
	for i := 0; i < retries; i++ {
		req, err := http.NewRequest(cleanMethod, targetURL, nil)
		if err != nil || req == nil {
			continue
		}
		req.Header.Set("Origin", origin)
		if cleanMethod == "OPTIONS" {
			req.Header.Set("Access-Control-Request-Method", "GET")
		}
		d.setDetectorHeaders(req)

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if allowOrigin == origin || d.isReflectionBypass(origin, allowOrigin) {
			return true
		}

		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}

	return false
}

func (d *Detector) verifyWithDifferentUA(targetURL, origin, method string) bool {
	cleanMethod := cleanHTTPMethod(method)
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		"Mozilla/5.0 (X11; Linux x86_64)",
		"curl/7.68.0",
		"Python-urllib/3.9",
	}

	successes := 0
	failures := 0

	for _, ua := range userAgents {
		req, err := http.NewRequest(cleanMethod, targetURL, nil)
		if err != nil || req == nil {
			failures++
			continue
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", ua)
		if cleanMethod == "OPTIONS" {
			req.Header.Set("Access-Control-Request-Method", "GET")
		}
		d.setDetectorHeaders(req)

		resp, err := d.client.Do(req)
		if err != nil {
			failures++
			continue
		}
		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if allowOrigin == origin || d.isReflectionBypass(origin, allowOrigin) {
			successes++
			if successes >= 3 {
				return true
			}
		} else {
			failures++
			if failures > len(userAgents)-3 {
				return false
			}
		}
	}

	// Must succeed with at least 3 different UAs
	return successes >= 3
}

func (d *Detector) verifyResponseConsistency(result *ScanResult) bool {
	cleanMethod := cleanHTTPMethod(result.Method)
	// Make two requests and compare
	req1, err1 := http.NewRequest(cleanMethod, result.URL, nil)
	if err1 != nil || req1 == nil {
		return false
	}
	req1.Header.Set("Origin", result.Origin)
	if cleanMethod == "OPTIONS" {
		req1.Header.Set("Access-Control-Request-Method", "GET")
	}
	d.setDetectorHeaders(req1)

	testOrigin := "https://non-existent-canary-origin.invalid"
	if result.Origin == testOrigin {
		testOrigin = "https://another-canary-domain.invalid"
	}

	req2, err2 := http.NewRequest(cleanMethod, result.URL, nil)
	if err2 != nil || req2 == nil {
		return false
	}
	req2.Header.Set("Origin", testOrigin)
	if cleanMethod == "OPTIONS" {
		req2.Header.Set("Access-Control-Request-Method", "GET")
	}
	d.setDetectorHeaders(req2)

	resp1, err := d.client.Do(req1)
	if err != nil {
		return false
	}
	ao1 := resp1.Header.Get("Access-Control-Allow-Origin")
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()

	resp2, err := d.client.Do(req2)
	if err != nil {
		return false
	}
	ao2 := resp2.Header.Get("Access-Control-Allow-Origin")
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	if result.Origin == "*" {
		return ao1 == "*"
	}

	return (ao1 != ao2 || ao2 == "") && (ao1 == result.Origin || d.isReflectionBypass(result.Origin, ao1))
}

func (d *Detector) isReflectionBypass(sent, received string) bool {
	// Check various bypass techniques

	// Exact match
	if sent == received {
		return true
	}

	// Null byte bypass
	cleaned := strings.ReplaceAll(sent, "\x00", "")
	if cleaned == received {
		return true
	}

	// URL decode comparison
	decoded, err := url.QueryUnescape(sent)
	if err == nil && decoded == received {
		return true
	}

	// Case insensitive for domain part
	if strings.EqualFold(sent, received) {
		return true
	}

	return false
}

// ClassifyVulnerability determines accurate vulnerability type
func (d *Detector) ClassifyVulnerability(result *ScanResult) string {
	origin := result.Origin
	allowOrigin := result.Headers["Access-Control-Allow-Origin"]

	// Wildcard
	if allowOrigin == "*" {
		return "Wildcard Origin (*)"
	}

	// Null origin
	if origin == "null" && allowOrigin == "null" {
		return "Null Origin Acceptance"
	}

	// Arbitrary reflection
	if origin == allowOrigin && !d.isTrustedOrigin(result.URL, origin) {
		return "Arbitrary Origin Reflection"
	}

	// Partial reflection
	if d.isPartialMatch(origin, allowOrigin) {
		return "Partial Origin Match Bypass"
	}

	// Backslash bypass
	if strings.Contains(origin, "\\") && strings.Contains(allowOrigin, "\\") {
		return "Backslash Bypass"
	}

	// @ symbol bypass
	if strings.Contains(origin, "@") {
		return "Authentication Bypass (@ Symbol)"
	}

	// Pre-domain bypass
	if strings.HasPrefix(allowOrigin, origin) || strings.HasSuffix(allowOrigin, origin) {
		return "Prefix/Suffix Bypass"
	}

	return "Generic CORS Misconfiguration"
}

func (d *Detector) isTrustedOrigin(targetURL, origin string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	domain := parsed.Hostname()
	if domain == "" {
		return false
	}

	// Check target domain and subdomains (case-insensitive, optional port and path/slash)
	pattern := `(?i)^https?://([a-z0-9-]+\.)?` + regexp.QuoteMeta(domain) + `(:\d+)?(/.*)?$`
	if matched, _ := regexp.MatchString(pattern, origin); matched {
		return true
	}

	for _, pat := range d.trustedPatterns {
		if matched, _ := regexp.MatchString(pat, origin); matched {
			return true
		}
	}
	return false
}

func (d *Detector) isPartialMatch(sent, received string) bool {
	// Check if one is prefix/suffix of other
	if strings.HasPrefix(received, sent) || strings.HasSuffix(received, sent) {
		return true
	}

	// Remove protocol and check domain
	sentDomain := extractDomainFromOrigin(sent)
	receivedDomain := extractDomainFromOrigin(received)

	if sentDomain != "" && receivedDomain != "" {
		if strings.HasSuffix(receivedDomain, sentDomain) ||
			strings.HasPrefix(receivedDomain, sentDomain) {
			return true
		}
	}

	return false
}

func extractDomainFromOrigin(origin string) string {
	origin = strings.TrimPrefix(origin, "https://")
	origin = strings.TrimPrefix(origin, "http://")

	if idx := strings.Index(origin, "/"); idx != -1 {
		origin = origin[:idx]
	}

	if idx := strings.Index(origin, ":"); idx != -1 {
		origin = origin[:idx]
	}

	return origin
}
