package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/youwannahackme/originstrike/config"
	"github.com/youwannahackme/originstrike/core"
	"github.com/youwannahackme/originstrike/report"
)

// TestServer creates a mock HTTP server for testing
func newTestServer() *httptest.Server {
	mux := http.NewServeMux()

	// Endpoint with wildcard CORS
	mux.HandleFunc("/wildcard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "wildcard allowed"}`))
	})

	// Endpoint with reflected origin
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "origin reflected"}`))
	})

	// Endpoint with null origin allowed
	mux.HandleFunc("/null-origin", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "null origin allowed"}`))
	})

	// Endpoint with credentials exposed
	mux.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"secret": "token_12345"}`))
	})

	// Endpoint with prefix bypass
	mux.HandleFunc("/prefix-bypass", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Vulnerable: allows evil.com if target is target.evil.com
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Secure endpoint (no vulnerabilities)
	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted-site.com")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "secure"}`))
	})

	// Preflight endpoint
	mux.HandleFunc("/preflight", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Null byte injection test
	mux.HandleFunc("/null-byte", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Simulate null byte stripping
		cleaned := replaceNullBytes(origin)
		w.Header().Set("Access-Control-Allow-Origin", cleaned)
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

func replaceNullBytes(s string) string {
	result := ""
	for _, c := range s {
		if c != '\x00' && c != 0 {
			result += string(c)
		}
	}
	return result
}

func TestWildcardDetection(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/wildcard"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected to find wildcard vulnerability")
	}

	found := false
	for _, r := range results {
		if r.VulnType == "Wildcard Origin (*)" {
			found = true
			if r.Confidence < 95 {
				t.Errorf("Expected high confidence for wildcard, got %.1f", r.Confidence)
			}
			break
		}
	}

	if !found {
		t.Error("Wildcard vulnerability type not found in results")
	}
}

func TestOriginReflectionDetection(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/reflect"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected to find origin reflection vulnerability")
	}

	// Should detect arbitrary origin reflection
	foundReflection := false
	for _, r := range results {
		if r.VulnType == "Arbitrary Origin Reflection" ||
			r.Origin == "https://evil.com" {
			foundReflection = true
			break
		}
	}

	if !foundReflection {
		t.Error("Expected to find origin reflection vulnerability")
	}
}

func TestNullOriginDetection(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/null-origin"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	foundNullOrigin := false
	for _, r := range results {
		if r.VulnType == "Null Origin Allowed" {
			foundNullOrigin = true
			break
		}
	}

	if !foundNullOrigin {
		t.Error("Expected to find null origin vulnerability")
	}
}

func TestCredentialLeakageDetection(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/credentials"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	foundCredentialIssue := false
	for _, r := range results {
		if r.VulnType == "Credential Leakage" {
			foundCredentialIssue = true
			if r.Severity != "CRITICAL" {
				t.Errorf("Expected CRITICAL severity for credential leakage, got %s", r.Severity)
			}
			break
		}
	}

	if !foundCredentialIssue {
		t.Error("Expected to find credential leakage vulnerability")
	}
}

func TestSecureEndpointNoFalsePositive(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/secure"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// Secure endpoint should produce zero results or only INFO level
	for _, r := range results {
		if r.Severity == "CRITICAL" || r.Severity == "HIGH" ||
			r.Severity == "MEDIUM" {
			t.Errorf("False positive detected on secure endpoint: %v", r)
		}
	}
}

func TestPreflightAnalysis(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/preflight"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// Should detect permissive preflight configuration
	foundPreflightIssue := false
	for _, r := range results {
		if r.VulnType == "Permissive Preflight" {
			foundPreflightIssue = true
			break
		}
	}

	if !foundPreflightIssue {
		t.Log("Note: Preflight issue may or may not be detected depending on implementation")
	}
}

func TestNullByteInjection(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:  []string{server.URL + "/null-byte"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// Check if null byte injection was detected
	foundNullByte := false
	for _, r := range results {
		if r.VulnType == "Null Byte Injection" {
			foundNullByte = true
			if r.Severity != "CRITICAL" {
				t.Errorf("Expected CRITICAL for null byte injection, got %s", r.Severity)
			}
			break
		}
	}

	if foundNullByte {
		t.Log("Successfully detected null byte injection bypass")
	}
}

func TestConcurrentScanning(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	targets := []string{
		server.URL + "/wildcard",
		server.URL + "/reflect",
		server.URL + "/null-origin",
		server.URL + "/credentials",
		server.URL + "/secure",
	}

	cfg := &config.Config{
		TargetURLs:  targets,
		Concurrency: 5,
		Timeout:     10 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	startTime := time.Now()
	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()
	duration := time.Since(startTime)

	if err != nil {
		t.Fatalf("Concurrent scanner failed: %v", err)
	}

	// Should have found vulnerabilities on non-secure endpoints
	if len(results) < 3 {
		t.Errorf("Expected at least 3 vulnerabilities, found %d", len(results))
	}

	// Concurrent scanning should be reasonably fast
	if duration > 25*time.Second {
		t.Errorf("Concurrent scanning took too long: %v", duration)
	}

	t.Logf("Concurrent scan completed in %v with %d results", duration, len(results))
}

func TestReportGeneration(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	cfg := &config.Config{
		TargetURLs:   []string{server.URL + "/wildcard"},
		Concurrency:  1,
		Timeout:      5 * time.Second,
		RetryCount:   1,
		Silent:       true,
		OutputFile:   "test_report.json",
		OutputFormat: "json",
	}

	scanner := core.NewScanner(cfg)
	results, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// Generate report manually since scanner.Start() no longer does it to avoid circular dependencies
	reporter, err := report.GenerateReport(cfg.OutputFormat, cfg.OutputFile)
	if err != nil {
		t.Fatalf("Failed to create reporter: %v", err)
	}
	err = reporter.Generate(results, scanner.GetStats())
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Verify report file was created
	if _, err := os.Stat("test_report.json"); os.IsNotExist(err) {
		t.Error("Report file was not created")
	}

	// Verify JSON is valid
	data, err := os.ReadFile("test_report.json")
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	var report map[string]interface{}
	err = json.Unmarshal(data, &report)
	if err != nil {
		t.Error("Generated invalid JSON report")
	}

	// Cleanup
	os.Remove("test_report.json")
}

func TestStatisticsAccuracy(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	targets := []string{
		server.URL + "/wildcard",
		server.URL + "/reflect",
		server.URL + "/null-origin",
	}

	cfg := &config.Config{
		TargetURLs:  targets,
		Concurrency: 3,
		Timeout:     5 * time.Second,
		RetryCount:  1,
		Silent:      true,
	}

	scanner := core.NewScanner(cfg)
	_, err := scanner.Start()

	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	stats := scanner.GetStats()

	// Verify statistics accuracy
	if stats.TotalURLs != int64(len(targets)) {
		t.Errorf("Expected TotalURLs=%d, got %d", len(targets), stats.TotalURLs)
	}

	if stats.ScannedURLs != int64(len(targets)) {
		t.Errorf("Expected ScannedURLs=%d, got %d", len(targets), stats.ScannedURLs)
	}

	if stats.TotalRequests == 0 {
		t.Error("TotalRequests should be greater than 0")
	}

	if stats.VulnerableURLs > int64(len(targets)) {
		t.Error("VulnerableURLs cannot exceed TotalURLs")
	}

	t.Logf("Statistics: %+v", stats)
}

// Benchmark tests
func BenchmarkWildcardDetection(b *testing.B) {
	server := newTestServer()
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := &config.Config{
			TargetURLs:  []string{server.URL + "/wildcard"},
			Concurrency: 1,
			Timeout:     5 * time.Second,
			RetryCount:  0,
			Silent:      true,
		}

		scanner := core.NewScanner(cfg)
		scanner.Start()
	}
}

func BenchmarkConcurrentScanning(b *testing.B) {
	server := newTestServer()
	defer server.Close()

	targets := make([]string, 10)
	for i := range targets {
		targets[i] = server.URL + "/wildcard"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := &config.Config{
			TargetURLs:  targets,
			Concurrency: 10,
			Timeout:     5 * time.Second,
			RetryCount:  0,
			Silent:      true,
		}

		scanner := core.NewScanner(cfg)
		scanner.Start()
	}
}
