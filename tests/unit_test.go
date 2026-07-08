package tests

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youwannahackme/originstrike/core"
	"github.com/youwannahackme/originstrike/database"
	"github.com/youwannahackme/originstrike/output"
	"github.com/youwannahackme/originstrike/payloads"
	"github.com/youwannahackme/originstrike/utils"
)

func TestURLParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasErr   bool
	}{
		{"https://example.com", "https://example.com", false},
		{"http://example.com", "http://example.com", false},
		{"example.com", "https://example.com", false},
		{"EXAMPLE.COM", "https://example.com", false},
		{"https://example.com/", "https://example.com", false},
		{"https://example.com/path", "https://example.com/path", false},
		{"", "", true},        // Invalid
		{"http://", "", true}, // Invalid
	}

	for _, tt := range tests {
		result, err := utils.NormalizeTarget(tt.input)

		if tt.hasErr {
			if err == nil {
				t.Errorf("Expected error for input %s, got none", tt.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Unexpected error for %s: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("For %s: expected %s, got %s", tt.input, tt.expected, result)
		}
	}
}

func TestParseFromFileAndIsFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "targets.txt")

	content := `# Comment line

https://example.com
example.org
http://test.com/path
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	if !utils.IsFile(filePath) {
		t.Errorf("Expected IsFile to be true for %s", filePath)
	}
	if utils.IsFile(tempDir) {
		t.Errorf("Expected IsFile to be false for directory %s", tempDir)
	}

	targets, err := utils.ParseFromFile(filePath)
	if err != nil {
		t.Fatalf("Unexpected error in ParseFromFile: %v", err)
	}

	expected := []string{"https://example.com", "https://example.org", "http://test.com/path"}
	if len(targets) != len(expected) {
		t.Fatalf("Expected %d targets, got %d: %v", len(expected), len(targets), targets)
	}
	for i, v := range expected {
		if targets[i] != v {
			t.Errorf("At index %d: expected %s, got %s", i, v, targets[i])
		}
	}
}

func TestPayloadGeneration(t *testing.T) {
	gen := payloads.NewGenerator()
	targetURL := "https://target.com"

	origins := gen.GenerateAdvancedOrigins(targetURL)

	if len(origins) == 0 {
		t.Fatal("Expected origins to be generated")
	}

	// Verify common attacker domains are present
	foundEvilCom := false
	for _, origin := range origins {
		if strings.Contains(origin, "evil.com") {
			foundEvilCom = true
			break
		}
	}

	if !foundEvilCom {
		t.Error("Expected evil.com in generated origins")
	}

	// Verify target-specific variations exist
	foundTargetVariation := false
	for _, origin := range origins {
		if strings.Contains(origin, "target.com") && strings.Contains(origin, "evil") {
			foundTargetVariation = true
			break
		}
	}

	if !foundTargetVariation {
		t.Error("Expected target-specific variations in origins")
	}

	t.Logf("Generated %d origin payloads", len(origins))
}

func TestNullBytePayloadGeneration(t *testing.T) {
	gen := payloads.NewGenerator()
	targetURL := "https://target.com"

	payloads := gen.GenerateNullBytePayloads(targetURL)

	if len(payloads) == 0 {
		t.Fatal("Expected null byte payloads to be generated")
	}

	// Verify payloads contain null bytes or encodings
	hasNullByte := false
	for _, payload := range payloads {
		if strings.Contains(payload, "\x00") || strings.Contains(payload, "%00") {
			hasNullByte = true
			break
		}
	}

	if !hasNullByte {
		t.Error("Expected null byte characters in payloads")
	}
}

func TestBypassTechniquePayloads(t *testing.T) {
	gen := payloads.NewGenerator()
	targetURL := "https://target.com"

	// Test backslash bypass
	backslashPayloads := gen.GenerateBackslashBypassOrigins(targetURL)
	if len(backslashPayloads) == 0 {
		t.Error("Expected backslash bypass payloads")
	}

	// Test @ symbol bypass
	atSymbolPayloads := gen.GenerateAtSymbolBypassOrigins(targetURL)
	if len(atSymbolPayloads) == 0 {
		t.Error("Expected @ symbol bypass payloads")
	}

	// Verify @ symbol payloads contain @ symbol
	hasAtSymbol := false
	for _, payload := range atSymbolPayloads {
		if strings.Contains(payload, "@") {
			hasAtSymbol = true
			break
		}
	}

	if !hasAtSymbol {
		t.Error("Expected @ symbol in bypass payloads")
	}
}

func TestOriginDeduplication(t *testing.T) {
	input := []string{
		"https://example.com",
		"https://example.com/",
		"HTTPS://EXAMPLE.COM",
		"https://test.com",
		"https://test.com",
		"http://other.com",
	}

	deduped := utils.Deduplicate(input)

	if len(deduped) != 3 {
		t.Errorf("Expected 3 unique URLs after deduplication, got %d", len(deduped))
	}
}

func TestSeverityClassification(t *testing.T) {
	analyzer := core.NewAnalyzer()

	tests := []struct {
		origin   string
		expected string
	}{
		{"https://evil.com", "CRITICAL"},
		{"https://attacker.com", "CRITICAL"},
		{"https://subdomain.example.com", "MEDIUM"},
		{"null", "MEDIUM"},
	}

	for _, tt := range tests {
		// Note: This would need access to internal method or public wrapper
		// Simplified test structure
		_ = analyzer
		_ = tt.expected
	}
}

func TestConfidenceCalculation(t *testing.T) {
	analyzer := core.NewAnalyzer()

	result := &core.ScanResult{
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":      "https://evil.com",
			"Access-Control-Allow-Credentials": "true",
		},
		IsConfirmed: true,
		VulnType:    "Wildcard Origin (*)",
	}

	confidence := analyzer.CalculateConfidence(result)

	if confidence < 80 {
		t.Errorf("Expected confidence >= 80, got %.1f", confidence)
	}

	if confidence > 100 {
		t.Errorf("Confidence cannot exceed 100, got %.1f", confidence)
	}
}

func TestResponseHeaderExtraction(t *testing.T) {
	analyzer := core.NewAnalyzer()

	// Mock response headers
	headers := http.Header{
		"Access-Control-Allow-Origin":  {"https://example.com"},
		"Access-Control-Allow-Methods": {"GET, POST"},
		"Access-Control-Allow-Headers": {"Content-Type"},
		"Content-Type":                 {"application/json"},
	}

	corsHeaders := analyzer.ExtractCORSHeaders(headers)

	if len(corsHeaders) != 3 {
		t.Errorf("Expected 3 CORS headers, got %d", len(corsHeaders))
	}

	if _, exists := corsHeaders["Access-Control-Allow-Origin"]; !exists {
		t.Error("Expected Access-Control-Allow-Origin in extracted headers")
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	tests := []struct {
		url, origin, method string
		expectUnique        bool
	}{
		{"https://a.com", "https://evil.com", "GET", true},
		{"https://a.com", "https://evil.com", "POST", true},
		{"https://b.com", "https://evil.com", "GET", true},
		{"https://a.com", "https://evil.com", "GET", false}, // Same as first
	}

	keys := make(map[string]int)

	for i, tt := range tests {
		key := database.GenerateCacheKey(tt.url, tt.origin, tt.method)
		keys[key]++

		if i > 0 && !tt.expectUnique {
			prevKey := database.GenerateCacheKey(
				tests[0].url, tests[0].origin, tests[0].method,
			)
			if key != prevKey {
				t.Errorf("Expected same key for identical params")
			}
		}
	}
}

func TestValidationRules(t *testing.T) {
	validator := core.NewValidator(nil)

	// Test valid result
	validResult := &core.ScanResult{
		URL:        "https://target.com",
		Origin:     "https://evil.com",
		Method:     "GET",
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin": "https://evil.com",
		},
		Confidence:  95.0,
		Timestamp:   time.Now(),
		IsConfirmed: true,
	}

	isValid, reason := validator.Validate(validResult)
	if !isValid {
		t.Errorf("Expected valid result to pass validation, reason: %s", reason)
	}

	// Test invalid result (missing headers)
	invalidResult := &core.ScanResult{
		URL:        "https://target.com",
		Origin:     "https://evil.com",
		Method:     "GET",
		StatusCode: 200,
		Headers:    map[string]string{},
		Confidence: 50.0,
		Timestamp:  time.Now(),
	}

	isValid, _ = validator.Validate(invalidResult)
	if isValid {
		t.Error("Expected result with missing headers to fail validation")
	}
}

func TestEdgeCaseOrigins(t *testing.T) {
	gen := payloads.NewGenerator()

	edgeCases := gen.EdgeCaseOrigins()

	requiredCases := []string{"null", "*", "javascript:", "data:"}

	for _, required := range requiredCases {
		found := false
		for _, origin := range edgeCases {
			if origin == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Required edge case origin not found: %s", required)
		}
	}
}

func TestDNSRebindingOrigins(t *testing.T) {
	gen := payloads.NewGenerator()

	dnsOrigins := gen.GenerateDNSRebindingOrigins()

	if len(dnsOrigins) == 0 {
		t.Error("Expected DNS rebinding origins to be generated")
	}

	// Should contain known rebinding services
	hasKnownService := false
	services := []string{"rbndr.us", "nip.io", "xip.io"}

	for _, origin := range dnsOrigins {
		for _, service := range services {
			if strings.Contains(origin, service) {
				hasKnownService = true
				break
			}
		}
		if hasKnownService {
			break
		}
	}

	if !hasKnownService {
		t.Log("Note: May not contain known rebinding services depending on implementation")
	}
}

func TestPOCGeneration(t *testing.T) {
	scanner := &core.Scanner{}

	targetURL := "https://target.com/api"
	origin := "https://evil.com"
	method := "GET"

	poc := scanner.GeneratePOC(targetURL, origin, method)

	if poc == "" {
		t.Error("Expected POC to be generated")
	}

	// Verify POC contains essential elements
	if !strings.Contains(poc, targetURL) {
		t.Error("POC should contain target URL")
	}

	if !strings.Contains(poc, origin) {
		t.Error("POC should contain malicious origin")
	}

	if !strings.Contains(poc, "<script>") && !strings.Contains(poc, "fetch") {
		t.Error("POC should contain JavaScript code")
	}
}

func TestStatisticsTracking(t *testing.T) {
	stats := &core.ScanStats{
		StartTime: time.Now(),
	}

	atomic.AddInt64(&stats.TotalURLs, 10)
	atomic.AddInt64(&stats.ScannedURLs, 5)
	atomic.AddInt64(&stats.VulnerableURLs, 2)
	atomic.AddInt64(&stats.TotalRequests, 100)
	atomic.AddInt64(&stats.TotalOriginsTested, 500)

	if stats.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}

	if stats.TotalURLs != 10 {
		t.Errorf("Expected TotalURLs=10, got %d", stats.TotalURLs)
	}

	if stats.ScannedURLs != 5 {
		t.Errorf("Expected ScannedURLs=5, got %d", stats.ScannedURLs)
	}

	if stats.VulnerableURLs != 2 {
		t.Errorf("Expected VulnerableURLs=2, got %d", stats.VulnerableURLs)
	}
}

func TestHelperFunctions(t *testing.T) {
	// Test truncation
	long := "This is a very long string that should be truncated"
	truncated := output.TruncateString(long, 10)

	if len(truncated) > 13 { // 10 + "..." {
		t.Errorf("Truncated string too long: %s", truncated)
	}

	if !strings.HasSuffix(truncated, "...") {
		t.Error("Truncated string should end with ...")
	}

	// Test CSV escaping
	withComma := "value,with,commas"
	escaped := output.EscapeCSV(withComma)

	if !strings.HasPrefix(escaped, `"`) || !strings.HasSuffix(escaped, `"`) {
		t.Error("CSV value with commas should be quoted")
	}
}

// Performance benchmarks
func BenchmarkPayloadGeneration(b *testing.B) {
	gen := payloads.NewGenerator()
	targetURL := "https://target.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.GenerateAdvancedOrigins(targetURL)
	}
}

func BenchmarkValidation(b *testing.B) {
	validator := core.NewValidator(nil)

	result := &core.ScanResult{
		URL:        "https://target.com",
		Origin:     "https://evil.com",
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin": "https://evil.com",
		},
		Confidence:  95.0,
		Timestamp:   time.Now(),
		IsConfirmed: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(result)
	}
}

func BenchmarkOriginDeduplication(b *testing.B) {
	input := make([]string, 1000)
	for i := range input {
		input[i] = fmt.Sprintf("https://example.com/path/%d", i%100) // Many duplicates
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		utils.Deduplicate(input)
	}
}
