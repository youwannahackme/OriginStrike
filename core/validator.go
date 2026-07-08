package core

import (
	"github.com/youwannahackme/originstrike/config"
	"github.com/youwannahackme/originstrike/utils"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Validator struct {
	config          *config.Config
	validationRules []ValidationRule
	cache           *ValidationCache
	mutex           sync.RWMutex
}

type ValidationRule struct {
	Name        string
	Description string
	Validate    func(*ScanResult) (bool, string)
	Weight      float64
}

type ValidationCache struct {
	entries map[string]*CachedValidation
	mutex   sync.RWMutex
}

type CachedValidation struct {
	Result    bool
	Reason    string
	Timestamp time.Time
}

func NewValidator(cfg *config.Config) *Validator {
	v := &Validator{
		config: cfg,
		cache: &ValidationCache{
			entries: make(map[string]*CachedValidation),
		},
	}

	v.setupValidationRules()

	return v
}

func (v *Validator) setupValidationRules() {
	v.validationRules = []ValidationRule{
		{
			Name:        "Origin Reflection Check",
			Description: "Verify origin is actually reflected in response",
			Validate:    v.checkOriginReflection,
			Weight:      30.0,
		},
		{
			Name:        "HTTP Status Validation",
			Description: "Confirm appropriate HTTP status codes",
			Validate:    v.checkStatusCode,
			Weight:      15.0,
		},
		{
			Name:        "Header Presence Check",
			Description: "Ensure required CORS headers are present",
			Validate:    v.checkHeaderPresence,
			Weight:      20.0,
		},
		{
			Name:        "False Positive Pattern Filter",
			Description: "Filter known false positive patterns",
			Validate:    v.filterFalsePositives,
			Weight:      25.0,
		},
		{
			Name:        "Consistency Verification",
			Description: "Verify result consistency across checks",
			Validate:    v.checkConsistency,
			Weight:      10.0,
		},
	}
}

func (v *Validator) ValidateAll(results []*ScanResult) []*ScanResult {
	var validatedResults []*ScanResult
	uniqueResults := make(map[string]*ScanResult)

	for _, result := range results {
		isValid, reason := v.Validate(result)
		if !isValid {
			if v.config.Verbose {
				logFilteredResult(result, reason)
			}
			continue
		}

		result.Confidence = v.calculateFinalConfidence(result)
		
		// Deduplicate results per URL and Vulnerability Type
		key := fmt.Sprintf("%s|%s", result.URL, result.VulnType)
		existing, exists := uniqueResults[key]
		if !exists {
			uniqueResults[key] = result
		} else {
			// Keep the one with higher confidence, or higher severity rank
			if result.Confidence > existing.Confidence ||
				(result.Confidence == existing.Confidence && severityRank(result.Severity) > severityRank(existing.Severity)) {
				uniqueResults[key] = result
			}
		}
	}

	for _, res := range uniqueResults {
		validatedResults = append(validatedResults, res)
	}

	// Sort by severity and confidence
	sort.Slice(validatedResults, func(i, j int) bool {
		if severityRank(validatedResults[i].Severity) != severityRank(validatedResults[j].Severity) {
			return severityRank(validatedResults[i].Severity) > severityRank(validatedResults[j].Severity)
		}
		return validatedResults[i].Confidence > validatedResults[j].Confidence
	})

	return validatedResults
}

func (v *Validator) Validate(result *ScanResult) (bool, string) {
	cacheKey := v.generateCacheKey(result)

	// Check cache
	if cached := v.getFromCache(cacheKey); cached != nil {
		if time.Since(cached.Timestamp) < time.Hour {
			return cached.Result, cached.Reason
		}
	}

	totalWeight := 0.0
	passedWeight := 0.0
	failureReasons := []string{}

	for _, rule := range v.validationRules {
		totalWeight += rule.Weight

		passed, reason := rule.Validate(result)
		if passed {
			passedWeight += rule.Weight
		} else {
			failureReasons = append(failureReasons, fmt.Sprintf("%s: %s", rule.Name, reason))
		}
	}

	// Calculate pass percentage (must be >= 80%)
	passPercentage := (passedWeight / totalWeight) * 100
	isValid := passPercentage >= 80.0

	reason := strings.Join(failureReasons, "; ")

	// Cache result
	v.addToCache(cacheKey, isValid, reason)

	return isValid, reason
}

func (v *Validator) checkOriginReflection(result *ScanResult) (bool, string) {
	allowOrigin, exists := result.Headers["Access-Control-Allow-Origin"]
	if !exists {
		return false, "Missing Access-Control-Allow-Origin header"
	}

	// For wildcard
	if result.Origin == "*" && allowOrigin == "*" {
		return true, ""
	}

	// For specific origins
	if allowOrigin == result.Origin {
		return true, ""
	}

	// For null byte bypass
	cleanedOrigin := strings.ReplaceAll(result.Origin, "\x00", "")
	cleanedOrigin = strings.ReplaceAll(cleanedOrigin, "%00", "")
	if cleanedOrigin == allowOrigin && cleanedOrigin != "" {
		return true, ""
	}

	return false, fmt.Sprintf("Origin mismatch: sent '%s', received '%s'", result.Origin, allowOrigin)
}

func (v *Validator) checkStatusCode(result *ScanResult) (bool, string) {
	// Valid status codes for CORS responses
	validStatuses := map[int]bool{
		200: true, 201: true, 202: true, 203: true, 204: true,
		206: true,
		301: true, 302: true, 303: true, 307: true, 308: true,
		401: true, 403: true, 405: true,
	}

	if validStatuses[result.StatusCode] {
		return true, ""
	}

	// Some status codes might still be valid depending on context
	if result.StatusCode >= 400 && result.StatusCode < 600 {
		// Error responses can still have valid CORS headers
		if len(result.Headers) > 0 {
			return true, ""
		}
	}

	return false, fmt.Sprintf("Suspicious status code: %d", result.StatusCode)
}

func (v *Validator) checkHeaderPresence(result *ScanResult) (bool, string) {
	// At least Access-Control-Allow-Origin must be present
	if _, exists := result.Headers["Access-Control-Allow-Origin"]; !exists {
		return false, "No CORS headers found in response"
	}

	// For certain vulnerability types, additional headers should be present
	if result.VulnType == "Credential Leakage" {
		if creds, exists := result.Headers["Access-Control-Allow-Credentials"]; !exists || creds != "true" {
			return false, "Missing or invalid Allow-Credentials header for credential leakage"
		}
	}

	return true, ""
}

func (v *Validator) filterFalsePositives(result *ScanResult) (bool, string) {
	// Known false positive patterns
	falsePositivePatterns := []struct {
		pattern string
		reason  string
	}{
		{"localhost", "Localhost testing - likely development environment"},
		{"127.0.0.1", "Loopback address - internal testing"},
		{"::1", "IPv6 loopback - internal testing"},
		{".local", "Local network - may be intentional"},
		{".internal", "Internal network - may be intentional"},
		{".dev", "Development environment"},
		{".test", "Testing environment"},
		{".example", "Example domain"},
	}

	// Parse the origin to extract the host accurately
	parsedOrigin, err := url.Parse(result.Origin)
	var originHost string
	if err == nil && parsedOrigin.Host != "" {
		originHost = parsedOrigin.Hostname()
	} else {
		// Fallback for null or malformed origin strings
		originHost = result.Origin
		if idx := strings.Index(originHost, "://"); idx != -1 {
			originHost = originHost[idx+3:]
		}
		if idx := strings.Index(originHost, "/"); idx != -1 {
			originHost = originHost[:idx]
		}
		if idx := strings.Index(originHost, ":"); idx != -1 {
			originHost = originHost[:idx]
		}
	}
	originHost = strings.ToLower(originHost)

	for _, fp := range falsePositivePatterns {
		matched := false
		if strings.HasPrefix(fp.pattern, ".") {
			// Suffix match (e.g. .local, .internal)
			if strings.HasSuffix(originHost, fp.pattern) {
				matched = true
			}
		} else {
			// Exact match (e.g. localhost, 127.0.0.1)
			if originHost == fp.pattern {
				matched = true
			}
		}

		if matched {
			// Only filter if not specifically targeting these
			if !v.isExplicitlyTargeting(result, fp.pattern) {
				return false, fp.reason
			}
		}
	}

	// Filter CDN/proxy responses that reflect origin by design
	cdnPatterns := []string{"cloudflare", "akamai", "fastly", "cloudfront"}
	for _, cdn := range cdnPatterns {
		if strings.Contains(strings.ToLower(result.URL), cdn) {
			// Additional validation needed for CDNs
			if !v.validateCDNResponse(result) {
				return false, "Potential CDN proxy behavior - requires manual verification"
			}
		}
	}

	return true, ""
}

func (v *Validator) checkConsistency(result *ScanResult) (bool, string) {
	// Ensure vulnerability type matches observed data
	switch result.VulnType {
	case "Wildcard Origin (*)":
		if result.Headers["Access-Control-Allow-Origin"] != "*" {
			return false, "Wildcard type but header doesn't contain *"
		}

	case "Null Origin Allowed", "Null Origin Acceptance":
		if result.Origin != "null" {
			return false, "Null origin type but origin is not null"
		}

	case "Credential Leakage":
		if result.Headers["Access-Control-Allow-Credentials"] != "true" {
			return false, "Credential leakage but Allow-Credentials is not true"
		}
	}

	// Check timestamp is recent (within last hour)
	if time.Since(result.Timestamp) > time.Hour {
		return false, "Result timestamp too old"
	}

	return true, ""
}

func (v *Validator) calculateFinalConfidence(result *ScanResult) float64 {
	baseConfidence := result.Confidence

	// Adjust based on validation results
	isValid, _ := v.Validate(result)
	if isValid {
		baseConfidence = baseConfidence * 1.1 // Boost if passes all validations
	}

	// Cap at 100
	if baseConfidence > 100 {
		baseConfidence = 100
	}

	return baseConfidence
}

func (v *Validator) generateCacheKey(result *ScanResult) string {
	headersStr := ""
	if result.Headers != nil {
		headersStr = result.Headers["Access-Control-Allow-Origin"] + "|" + result.Headers["Access-Control-Allow-Credentials"]
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s", result.URL, result.Origin, result.Method, result.StatusCode, headersStr)
}

func (v *Validator) getFromCache(key string) *CachedValidation {
	v.cache.mutex.RLock()
	defer v.cache.mutex.RUnlock()

	return v.cache.entries[key]
}

func (v *Validator) addToCache(key string, result bool, reason string) {
	v.cache.mutex.Lock()
	defer v.cache.mutex.Unlock()

	v.cache.entries[key] = &CachedValidation{
		Result:    result,
		Reason:    reason,
		Timestamp: time.Now(),
	}
}

func (v *Validator) isExplicitlyTargeting(result *ScanResult, pattern string) bool {
	targetURL, err := url.Parse(result.URL)
	if err != nil {
		return false
	}
	targetHost := strings.ToLower(targetURL.Hostname())
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(targetHost, pattern)
	}
	return targetHost == pattern
}

func (v *Validator) validateCDNResponse(result *ScanResult) bool {
	// CDN-specific validation logic
	// This would check for actual exploitation potential
	return result.Confidence >= 90.0
}

func severityRank(severity string) int {
	ranks := map[string]int{
		"CRITICAL": 5,
		"HIGH":     4,
		"MEDIUM":   3,
		"LOW":      2,
		"INFO":     1,
	}

	if rank, exists := ranks[severity]; exists {
		return rank
	}
	return 0
}

func logFilteredResult(result *ScanResult, reason string) {
	utils.LogInfo("Filtered result for %s: %s (Reason: %s)", result.URL, result.VulnType, reason)
}
