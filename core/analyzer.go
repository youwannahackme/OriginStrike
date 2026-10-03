package core

import (
	"net/http"
	"regexp"
	"strings"
)

type Analyzer struct {
	corsHeaderPatterns map[string]*regexp.Regexp
	dangerousMethods   []string
	dangerousHeaders   []string
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		corsHeaderPatterns: map[string]*regexp.Regexp{
			"Access-Control-Allow-Origin":      regexp.MustCompile(`(?i)^.+$`),
			"Access-Control-Allow-Methods":     regexp.MustCompile(`(?i)^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)(,\s*(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH))*$`),
			"Access-Control-Allow-Headers":     regexp.MustCompile(`(?i)^.+$`),
			"Access-Control-Allow-Credentials": regexp.MustCompile(`(?i)^(true|false)$`),
			"Access-Control-Max-Age":           regexp.MustCompile(`^\d+$`),
			"Access-Control-Expose-Headers":    regexp.MustCompile(`(?i)^.+$`),
		},
		dangerousMethods: []string{"DELETE", "PUT", "PATCH", "TRACE"},
		dangerousHeaders: []string{"Authorization", "Cookie", "X-CSRF-Token"},
	}
}

func (a *Analyzer) ExtractCORSHeaders(headers http.Header) map[string]string {
	corsHeaders := make(map[string]string)

	corsHeaderNames := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Credentials",
		"Access-Control-Max-Age",
		"Access-Control-Expose-Headers",
	}

	for _, name := range corsHeaderNames {
		if value := headers.Get(name); value != "" {
			corsHeaders[name] = value
		}
	}

	return corsHeaders
}

func (a *Analyzer) IsOriginReflected(sentOrigin, receivedOrigin string) bool {
	if sentOrigin == receivedOrigin {
		return true
	}

	// Handle URL-encoded origins
	if a.urlDecode(sentOrigin) == receivedOrigin {
		return true
	}

	// Handle case variations
	if strings.EqualFold(sentOrigin, receivedOrigin) {
		return true
	}

	return false
}

func (a *Analyzer) IsPartialReflection(sentOrigin, receivedOrigin string) bool {
	sentClean := a.cleanOrigin(sentOrigin)
	receivedClean := a.cleanOrigin(receivedOrigin)

	// Prefix match
	if strings.HasPrefix(receivedClean, sentClean) && receivedClean != sentClean {
		return true
	}

	// Suffix match
	if strings.HasSuffix(receivedClean, sentClean) && receivedClean != sentClean {
		return true
	}

	// Contains match
	if strings.Contains(receivedClean, sentClean) && receivedClean != sentClean {
		return true
	}

	return false
}

func (a *Analyzer) IsNullByteBypassSuccessful(payload, response string) bool {
	// Remove null bytes from payload
	cleaned := strings.ReplaceAll(payload, "\x00", "")
	cleaned = strings.ReplaceAll(cleaned, "%00", "")

	// If response matches cleaned version, bypass successful
	return cleaned == response && cleaned != ""
}

func (a *Analyzer) IsOverlyPermissiveMethods(methods string) bool {
	if methods == "" {
		return false
	}

	methodList := strings.Split(methods, ",")
	for _, method := range methodList {
		method = strings.TrimSpace(strings.ToUpper(method))
		for _, dangerous := range a.dangerousMethods {
			if method == dangerous {
				return true
			}
		}
	}

	// Wildcard in methods
	if strings.Contains(methods, "*") {
		return true
	}

	return false
}

func (a *Analyzer) IsOverlyPermissiveHeaders(headers string) bool {
	if headers == "" {
		return false
	}

	// Wildcard
	if strings.Contains(headers, "*") {
		return true
	}

	headerList := strings.Split(headers, ",")
	for _, header := range headerList {
		header = strings.TrimSpace(header)
		for _, dangerous := range a.dangerousHeaders {
			if strings.EqualFold(header, dangerous) {
				return true
			}
		}
	}

	return false
}

func (a *Analyzer) ShouldHaveCORS(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	// Heuristic: API endpoints should have CORS
	contentType := resp.Header.Get("Content-Type")
	apiPatterns := []string{
		"application/json",
		"application/xml",
		"api/",
		"/v1/", "/v2/", "/v3/",
	}

	reqPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		reqPath = resp.Request.URL.Path
	}

	for _, pattern := range apiPatterns {
		if strings.Contains(contentType, pattern) ||
			(reqPath != "" && strings.Contains(reqPath, pattern)) {
			return true
		}
	}

	return false
}

func (a *Analyzer) cleanOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	origin = strings.TrimRight(origin, "/")
	return origin
}

func (a *Analyzer) urlDecode(s string) string {
	decoded := s
	// Simple URL decode for common patterns
	replacements := map[string]string{
		"%3A": ":",
		"%2F": "/",
		"%40": "@",
		"%26": "&",
		"%3D": "=",
		"%23": "#",
	}

	for encoded, decodedChar := range replacements {
		decoded = strings.ReplaceAll(decoded, encoded, decodedChar)
	}

	return decoded
}

// CalculateConfidence calculates confidence score (0-100)
func (a *Analyzer) CalculateConfidence(result *ScanResult) float64 {
	confidence := 50.0 // Base confidence

	// Factor 1: HTTP status code
	if result.StatusCode >= 200 && result.StatusCode < 300 {
		confidence += 20
	}

	// Factor 2: Presence of multiple CORS headers
	if len(result.Headers) >= 2 {
		confidence += 15
	}

	// Factor 3: Specific vulnerability type weights
	switch result.VulnType {
	case "Wildcard Origin (*)":
		confidence += 25
	case "Credential Leakage":
		confidence += 20
	case "Null Byte Injection":
		confidence += 15
	case "Arbitrary Origin Reflection":
		confidence += 10
	}

	// Factor 4: Consistency checks
	if result.IsConfirmed {
		confidence += 10
	}

	// Cap at 100
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
