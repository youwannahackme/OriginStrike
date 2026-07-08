package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/youwannahackme/originstrike/config"
)

type Client struct {
	httpClient  *http.Client
	config      *config.Config
	jar         http.CookieJar
	rateLimiter chan time.Time
}

type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    io.Reader
	Cookies []*http.Cookie
}

type Response struct {
	StatusCode  int
	Headers     http.Header
	Body        string
	RequestURL  string
	Duration    time.Duration
	RawResponse *http.Response
}

func NewClient(cfg *config.Config) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   10,
	}

	jar, _ := cookiejar.New(nil)

	client := &Client{
		httpClient: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if cfg.FollowRedirect {
					return nil
				}
				return http.ErrUseLastResponse
			},
		},
		config:      cfg,
		jar:         jar,
		rateLimiter: make(chan time.Time, cfg.Concurrency),
	}

	// Initialize rate limiter
	if cfg.Delay > 0 {
		go client.initRateLimiter()
	}

	return client
}

func (c *Client) initRateLimiter() {
	ticker := time.NewTicker(c.config.Delay)
	defer ticker.Stop()

	for t := range ticker.C {
		select {
		case c.rateLimiter <- t:
		default:
			// Drop if full
		}
	}
}

func (c *Client) DoRequest(targetURL, method string, customHeaders map[string]string, body io.Reader) (*Response, error) {
	// Rate limiting
	if c.config.Delay > 0 {
		<-c.rateLimiter
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Add scheme if missing
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		targetURL = parsedURL.String()
	}

	// Create request
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	c.setDefaultHeaders(req)

	// Set custom headers
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Set config custom headers
	for key, value := range c.config.CustomHeaders {
		if _, exists := req.Header[key]; !exists {
			req.Header.Set(key, value)
		}
	}

	// Set Cookie header if configured and not overridden
	if c.config.Cookie != "" {
		if _, exists := req.Header["Cookie"]; !exists {
			req.Header.Set("Cookie", c.config.Cookie)
		}
	}

	// Perform request with retry logic
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		startTime := time.Now()
		resp, err = c.httpClient.Do(req)
		duration := time.Since(startTime)

		if err == nil {
			return c.parseResponse(resp, duration)
		}

		lastErr = err

		// Don't retry on certain errors
		if isNonRetryableError(err) {
			break
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.RetryCount+1, lastErr)
}

func (c *Client) DoRequestWithCredentials(targetURL, method string, customHeaders map[string]string, body io.Reader) (*Response, error) {
	// Clone headers and add credential-related headers
	headers := make(map[string]string)
	for k, v := range customHeaders {
		headers[k] = v
	}

	// Ensure credentials are included
	if _, exists := headers["Cookie"]; !exists {
		if c.config.Cookie != "" {
			headers["Cookie"] = c.config.Cookie
		} else {
			headers["Cookie"] = "session=test-session-id; auth=test-token"
		}
	}

	resp, err := c.DoRequest(targetURL, method, headers, body)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) DoPreflightRequest(targetURL string, headers map[string]string) (*Response, error) {
	// Set preflight-specific headers
	if _, exists := headers["Access-Control-Request-Method"]; !exists {
		headers["Access-Control-Request-Method"] = "GET"
	}

	return c.DoRequest(targetURL, "OPTIONS", headers, nil)
}

func (c *Client) setDefaultHeaders(req *http.Request) {
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// Sec-Fetch headers (modern browsers send these)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
}

func (c *Client) parseResponse(resp *http.Response, duration time.Duration) (*Response, error) {
	defer resp.Body.Close()

	// Read body
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Limit to 10MB
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header.Clone(),
		Body:        string(bodyBytes),
		RequestURL:  resp.Request.URL.String(),
		Duration:    duration,
		RawResponse: resp,
	}, nil
}

func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func isNonRetryableError(err error) bool {
	errStr := err.Error()

	nonRetryablePatterns := []string{
		"invalid URL",
		"unsupported protocol",
		"timeout exceeded", // Already handled by client timeout
		"context canceled",
	}

	for _, pattern := range nonRetryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}
