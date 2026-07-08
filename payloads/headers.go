package payloads

import (
    "fmt"
    "math/rand"
    "strings"
    "time"
)

// HeaderGenerator creates sophisticated HTTP header combinations for bypass testing
type HeaderGenerator struct {
    randSource *rand.Rand
}

// HeaderSet represents a collection of headers for a single request
type HeaderSet struct {
    Origin         string
    CustomHeaders  map[string]string
    Priority       int        // 1-10, higher = more likely to trigger vuln
    Description    string     // Human-readable description
    Category       string     // Classification: "standard", "bypass", "edge-case", "malformed"
    BypassType     string     // Specific technique this targets
    DangerLevel    string     // "low", "medium", "high", "critical"
}

// HeaderVariation represents different ways to send the same header
type HeaderVariation struct {
    HeaderName  string
    HeaderValue string
    Encoding    string // "normal", "url-encoded", "double-encoded", "unicode", "mixed-case"
    Purpose     string // Why this variation exists
}

func NewHeaderGenerator() *HeaderGenerator {
    return &HeaderGenerator{
        randSource: rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

// GenerateAllHeaderVariations produces comprehensive header test matrix
func (hg *HeaderGenerator) GenerateAllHeaderVariations(targetOrigin string, targetURL string) []HeaderSet {
    var allHeaders []HeaderSet
    
    // Category 1: Standard CORS Headers (baseline)
    allHeaders = append(allHeaders, hg.generateStandardCORSHeaders(targetOrigin)...)
    
    // Category 2: Origin Header Manipulations
    allHeaders = append(allHeaders, hg.generateOriginManipulations(targetOrigin)...)
    
    // Category 3: Sec-Fetch Header Variations
    allHeaders = append(allHeaders, hg.generateSecFetchVariations()...)
    
    // Category 4: Request Header Bypasses
    allHeaders = append(allHeaders, hg.generateRequestHeaderBypasses(targetOrigin)...)
    
    // Category 5: Malformed/Edge Case Headers
    allHeaders = append(allHeaders, hg.generateMalformedHeaders(targetOrigin)...)
    
    // Category 6: Encoding-Based Variations
    allHeaders = append(allHeaders, hg.generateEncodingBasedHeaders(targetOrigin)...)
    
    // Category 7: Browser-Spoofing Headers
    allHeaders = append(allHeaders, hg.generateBrowserSpoofingHeaders(targetOrigin)...)
    
    // Category 8: Credential & Auth Header Tests
    allHeaders = append(allHeaders, hg.generateCredentialHeaders(targetOrigin)...)
    
    // Category 9: Preflight-Specific Headers
    allHeaders = append(allHeaders, hg.generatePreflightHeaders(targetOrigin)...)
    
    // Category 10: Advanced Bypass Combinations
    allHeaders = append(allHeaders, hg.generateAdvancedBypassCombinations(targetOrigin, targetURL)...)
    
    return allHeaders
}

// ============================================================
// CATEGORY 1: STANDARD CORS HEADERS (Baseline Testing)
// ============================================================

func (hg *HeaderGenerator) generateStandardCORSHeaders(origin string) []HeaderSet {
    return []HeaderSet{
        {
            Origin:      origin,
            CustomHeaders: map[string]string{
                "Origin": origin,
            },
            Priority:    5,
            Description: "Standard Origin header",
            Category:    "standard",
            BypassType:  "none",
            DangerLevel: "low",
        },
        {
            Origin:      origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Sec-Fetch-Dest":           "empty",
                "Sec-Fetch-Mode":           "cors",
                "Sec-Fetch-Site":           "cross-site",
            },
            Priority:    6,
            Description: "Origin with standard browser security headers",
            Category:    "standard",
            BypassType:  "none",
            DangerLevel: "low",
        },
        {
            Origin:      origin,
            CustomHeaders: map[string]string{
                "Origin":              origin,
                "Accept":             "*/*",
                "Accept-Language":    "en-US,en;q=0.9",
                "Accept-Encoding":    "gzip, deflate, br",
            },
            Priority:    4,
            Description: "Origin with full accept headers",
            Category:    "standard",
            BypassType:  "none",
            DangerLevel: "low",
        },
    }
}

// ============================================================
// CATEGORY 2: ORIGIN HEADER MANIPULATIONS
// ============================================================

func (hg *HeaderGenerator) generateOriginManipulations(origin string) []HeaderSet {
    return []HeaderSet{
        // Duplicate Origin headers
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin": origin,
            },
            Priority:    7,
            Description: "Single Origin header (control)",
            Category:    "bypass",
            BypassType:  "header-injection",
            DangerLevel: "medium",
        },
        
        // Origin with X-Forwarded-For spoofing
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":          origin,
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP":       "127.0.0.1",
                "X-Original-URL":  "/admin",
            },
            Priority:    8,
            Description: "Origin with internal IP spoofing headers",
            Category:    "bypass",
            BypassType:  "ip-spoofing",
            DangerLevel: "high",
        },
        
        // Origin with Referer manipulation
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":  origin,
                "Referer": origin + "/page",
            },
            Priority:    6,
            Description: "Origin with matching Referer header",
            Category:    "bypass",
            BypassType:  "referer-spoofing",
            DangerLevel: "medium",
        },
        
        // Origin with conflicting Referer
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":  origin,
                "Referer": "https://trusted-site.com/",
            },
            Priority:    7,
            Description: "Origin with mismatched Referer (confusion attack)",
            Category:    "bypass",
            BypassType:  "header-confusion",
            DangerLevel: "medium",
        },
        
        // Empty Origin with fallback attempts
        {
            Origin: "",
            CustomHeaders: map[string]string{
                "Origin": "",
            },
            Priority:    5,
            Description: "Empty Origin header",
            Category:    "edge-case",
            BypassType:  "empty-header",
            DangerLevel: "low",
        },
        
        // Multiple space-padded origins
        {
            Origin: " " + origin + " ",
            CustomHeaders: map[string]string{
                "Origin": " " + origin + " ",
            },
            Priority:    7,
            Description: "Space-padded Origin (whitespace bypass)",
            Category:    "bypass",
            BypassType:  "whitespace-injection",
            DangerLevel: "medium",
        },
        
        // Tab-padded origin
        {
            Origin: "\t" + origin,
            CustomHeaders: map[string]string{
                "Origin": "\t" + origin,
            },
            Priority:    7,
            Description: "Tab-padded Origin (tab injection)",
            Category:    "bypass",
            BypassType:  "tab-injection",
            DangerLevel: "medium",
        },
        
        // Newline in origin (header injection attempt)
        {
            Origin: origin + "\r\nX-Injected: true",
            CustomHeaders: map[string]string{
                "Origin": origin + "\r\nX-Injected: true",
            },
            Priority:    9,
            Description: "CRLF injection in Origin (HTTP header splitting)",
            Category:    "malformed",
            BypassType:  "crlf-injection",
            DangerLevel: "critical",
        },
        
        // Origin with line feed only
        {
            Origin: origin + "\nX-Test: injected",
            CustomHeaders: map[string]string{
                "Origin": origin + "\nX-Test: injected",
            },
            Priority:    8,
            Description: "LF injection in Origin",
            Category:    "malformed",
            BypassType:  "lf-injection",
            DangerLevel: "critical",
        },
    }
}

// ============================================================
// CATEGORY 3: SEC-FETCH HEADER VARIATIONS
// ============================================================

func (hg *HeaderGenerator) generateSecFetchVariations() []HeaderSet {
    secFetchModes := []struct {
        dest  string
        mode  string
        site  string
        desc  string
    }{
        {"document", "navigate", "none", "Top-level navigation"},
        {"empty", "cors", "cross-site", "Standard cross-origin fetch"},
        {"empty", "no-cors", "cross-site", "No-CORS mode request"},
        {"empty", "same-origin", "same-origin", "Same-origin request (spoofed)"},
        {"iframe", "embed", "cross-site", "Embedded in iframe"},
        {"object", "embed", "cross-site", "Object embed"},
        {"script", "no-cors", "cross-site", "Script loading context"},
        {"worker", "same-origin", "same-origin", "Web Worker context"},
        {"sharedworker", "same-origin", "same-origin", "Shared Worker context"},
        {"audio", "no-cors", "cross-site", "Audio resource fetch"},
        {"video", "no-cors", "cross-site", "Video resource fetch"},
        {"track", "no-cors", "cross-site", "Track resource fetch"},
        {"font", "no-cors", "cross-site", "Font resource fetch"},
        {"image", "no-cors", "cross-site", "Image resource fetch"},
        {"manifest", "cors", "cross-site", "Manifest fetch"},
        {"fencedframe", "embed", "cross-site", "Fenced frame embed"},
        {"report", "no-cors", "cross-site", "Reporting endpoint"},
        {"", "", "", "Missing all Sec-Fetch headers"},
    }
    
    var variations []HeaderSet
    
    for _, sf := range secFetchModes {
        headers := make(map[string]string)
        
        if sf.dest != "" {
            headers["Sec-Fetch-Dest"] = sf.dest
        }
        if sf.mode != "" {
            headers["Sec-Fetch-Mode"] = sf.mode
        }
        if sf.site != "" {
            headers["Sec-Fetch-Site"] = sf.site
        }
        
        priority := 5
        danger := "low"
        
        // Higher priority for suspicious combinations
        if sf.mode == "no-cors" && sf.site == "same-origin" {
            priority = 8
            danger = "medium"
        }
        if sf.dest == "document" && sf.site != "none" {
            priority = 8
            danger = "medium"
        }
        if sf.dest == "" && sf.mode == "" && sf.site == "" {
            priority = 6
            danger = "low"
        }
        
        variations = append(variations, HeaderSet{
            Origin:        "https://evil.com",
            CustomHeaders: headers,
            Priority:      priority,
            Description:   fmt.Sprintf("Sec-Fetch: %s", sf.desc),
            Category:      "browser-spoofing",
            BypassType:    "sec-fetch-manipulation",
            DangerLevel:   danger,
        })
    }
    
    return variations
}

// ============================================================
// CATEGORY 4: REQUEST HEADER BYPASSES
// ============================================================

func (hg *HeaderGenerator) generateRequestHeaderBypasses(origin string) []HeaderSet {
    return []HeaderSet{
        // X-Forwarded-Host bypass
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":           origin,
                "X-Forwarded-Host": "evil.com",
                "Host":             "target.com",
            },
            Priority:    9,
            Description: "X-Forwarded-Host header injection for host confusion",
            Category:    "bypass",
            BypassType:  "host-confusion",
            DangerLevel: "high",
        },
        
        // X-Original-URL bypass
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":          origin,
                "X-Original-URL":  "/api/admin",
                "X-Rewrite-URL":  "/api/admin",
            },
            Priority:    8,
            Description: "X-Original-URL path bypass attempt",
            Category:    "bypass",
            BypassType:  "path-bypass",
            DangerLevel: "high",
        },
        
        // X-HTTP-Method-Override
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                origin,
                "X-HTTP-Method-Override": "DELETE",
                "X-Method-Override":     "PUT",
            },
            Priority:    8,
            Description: "HTTP method override headers (verb tampering)",
            Category:    "bypass",
            BypassType:  "method-tampering",
            DangerLevel: "high",
        },
        
        // Content-Type manipulation
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":      origin,
                "Content-Type": "text/plain",
                "X-Content-Type-Options": "nosniff",
            },
            Priority:    6,
            Description: "Content-Type manipulation with nosniff bypass",
            Category:    "bypass",
            BypassType:  "content-type-confusion",
            DangerLevel: "medium",
        },
        
        // Various Accept header bypasses
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":            origin,
                "Accept":           "text/html,application/xhtml+xml",
                "Accept-Charset":    "utf-8",
            },
            Priority:    5,
            Description: "HTML Accept header (may trigger different handling)",
            Category:    "bypass",
            BypassType:  "accept-manipulation",
            DangerLevel: "low",
        },
        
        // Via header (proxy indication)
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":        origin,
                "Via":           "1.1 evil.com (proxy)",
                "X-Forwarded-By": "evil.com",
            },
            Priority:    7,
            Description: "Via header indicating proxy traversal",
            Category:    "bypass",
            BypassType:  "proxy-spoofing",
            DangerLevel: "medium",
        },
        
        // Connection header tricks
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":             origin,
                "Connection":         "keep-alive, Upgrade",
                "Upgrade":            "h2c, websocket",
                "Upgrade-Insecure-Requests": "1",
            },
            Priority:    6,
            Description: "Connection upgrade headers",
            Category:    "edge-case",
            BypassType:  "protocol-upgrade",
            DangerLevel: "low",
        },
        
        // Cache control bypass
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":          origin,
                "Cache-Control":   "no-cache, no-store, must-revalidate",
                "Pragma":          "no-cache",
                "If-None-Match":   "\"weak-etag\"",
                "If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT",
            },
            Priority:    4,
            Description: "Cache busting headers (ensure fresh response)",
            Category:    "standard",
            BypassType:  "cache-busting",
            DangerLevel: "low",
        },
        
        // Conditional request bypass
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":        origin,
                "If-Match":      "\"strong-etag\"",
                "If-Unmodified-Since": time.Now().Add(24 * time.Hour).Format(time.RFC1123),
            },
            Priority:    5,
            Description: "Conditional request headers",
            Category:    "edge-case",
            BypassType:  "conditional-request",
            DangerLevel: "low",
        },
    }
}

// ============================================================
// CATEGORY 5: MALFORMED / EDGE CASE HEADERS
// ============================================================

func (hg *HeaderGenerator) generateMalformedHeaders(origin string) []HeaderSet {
	_ = origin
    return []HeaderSet{
        // Extremely long origin
        {
            Origin: strings.Repeat("a.", 100) + "evil.com",
            CustomHeaders: map[string]string{
                "Origin": strings.Repeat("a.", 100) + "evil.com",
            },
            Priority:    6,
            Description: "Extremely long subdomain origin (buffer overflow test)",
            Category:    "malformed",
            BypassType:  "long-string",
            DangerLevel: "medium",
        },
        
        // Unicode normalization attacks
        {
            Origin: "https://evıl.com",  // dotless i
            CustomHeaders: map[string]string{
                "Origin": "https://evıl.com",
            },
            Priority:    7,
            Description: "Unicode homograph attack (dotless i)",
            Category:    "malformed",
            BypassType:  "unicode-homograph",
            DangerLevel: "high",
        },
        
        // Full-width characters
        {
            Origin: "https://ｅｖｉｌ.com",
            CustomHeaders: map[string]string{
                "Origin": "https://ｅｖｉｌ.com",
            },
            Priority:    7,
            Description: "Full-width character origin (visual spoof)",
            Category:    "malformed",
            BypassType:  "fullwidth-spoof",
            DangerLevel: "high",
        },
        
        // Mixed script (Greek + Latin)
        {
            Origin: "https://еvіl.com",  // Cyrillic e and i
            CustomHeaders: map[string]string{
                "Origin": "https://еvіl.com",
            },
            Priority:    8,
            Description: "Mixed-script homograph attack (Cyrillic chars)",
            Category:    "malformed",
            BypassType:  "mixed-script",
            DangerLevel: "critical",
        },
        
        // Origin with control characters
        {
            Origin: "https://evil\x01.com",
            CustomHeaders: map[string]string{
                "Origin": "https://evil\x01.com",
            },
            Priority:    8,
            Description: "Control character in domain (SOH)",
            Category:    "malformed",
            BypassType:  "control-character",
            DangerLevel: "high",
        },
        
        // Origin with backspace characters
        {
            Origin: "https://evil\b.com",
            CustomHeaders: map[string]string{
                "Origin": "https://evil\b.com",
            },
            Priority:    7,
            Description: "Backspace character in domain",
            Category:    "malformed",
            BypassType:  "backspace-injection",
            DangerLevel: "high",
        },
        
        // Punycode abuse
        {
            Origin: "https://xn--evil-xxxx.com",  // Fake punycode
            CustomHeaders: map[string]string{
                "Origin": "https://xn--evil-xxxx.com",
            },
            Priority:    6,
            Description: "Punycode encoding abuse",
            Category:    "malformed",
            BypassType:  "punycode-abuse",
            DangerLevel: "medium",
        },
        
        // IP address variations
        {
            Origin: "https://0x7f000001",  // 127.0.0.1 in hex
            CustomHeaders: map[string]string{
                "Origin": "https://0x7f000001",
            },
            Priority:    7,
            Description: "Hexadecimal IP address (localhost)",
            Category:    "malformed",
            BypassType:  "ip-format-variation",
            DangerLevel: "high",
        },
        
        // Octal IP
        {
            Origin: "https://017700000001",  // 127.0.0.1 in octal
            CustomHeaders: map[string]string{
                "Origin": "https://017700000001",
            },
            Priority:    7,
            Description: "Octal IP address representation",
            Category:    "malformed",
            BypassType:  "ip-format-variation",
            DangerLevel: "high",
        },
        
        // Decimal IP
        {
            Origin: "https://2130706433",  // 127.0.0.1 as decimal
            CustomHeaders: map[string]string{
                "Origin": "https://2130706433",
            },
            Priority:    7,
            Description: "Decimal IP address representation",
            Category:    "malformed",
            BypassType:  "ip-format-variation",
            DangerLevel: "high",
        },
        
        // Shorthand IP addresses
        {
            Origin: "https://127.1",
            CustomHeaders: map[string]string{
                "Origin": "https://127.1",
            },
            Priority:    6,
            Description: "Shorthand IP notation (127.0.0.1)",
            Category:    "malformed",
            BypassType:  "ip-shorthand",
            DangerLevel: "medium",
        },
        
        // IPv6 variations
        {
            Origin: "https://[::1]",
            CustomHeaders: map[string]string{
                "Origin": "https://[::1]",
            },
            Priority:    6,
            Description: "IPv6 loopback address",
            Category:    "malformed",
            BypassType:  "ipv6-loopback",
            DangerLevel: "medium",
        },
        
        // IPv6-mapped IPv4
        {
            Origin: "https://[::ffff:127.0.0.1]",
            CustomHeaders: map[string]string{
                "Origin": "https://[::ffff:127.0.0.1]",
            },
            Priority:    6,
            Description: "IPv6-mapped IPv4 loopback",
            Category:    "malformed",
            BypassType:  "ipv6-mapped",
            DangerLevel: "medium",
        },
        
        // Origin with port 0
        {
            Origin: "https://evil.com:0",
            CustomHeaders: map[string]string{
                "Origin": "https://evil.com:0",
            },
            Priority:    5,
            Description: "Port 0 (ephemeral port bypass)",
            Category:    "edge-case",
            BypassType:  "port-zero",
            DangerLevel: "low",
        },
        
        // Very high port number
        {
            Origin: "https://evil.com:65535",
            CustomHeaders: map[string]string{
                "Origin": "https://evil.com:65535",
            },
            Priority:    5,
            Description: "Maximum port number",
            Category:    "edge-case",
            BypassType:  "port-extreme",
            DangerLevel: "low",
        },
    }
}

// ============================================================
// CATEGORY 6: ENCODING-BASED VARIATIONS
// ============================================================

func (hg *HeaderGenerator) generateEncodingBasedHeaders(origin string) []HeaderSet {
	_ = origin
    return []HeaderSet{
        // URL-encoded origin
        {
            Origin: "https%3A%2F%2Fevil.com",
            CustomHeaders: map[string]string{
                "Origin": "https%3A%2F%2Fevil.com",
            },
            Priority:    7,
            Description: "Fully URL-encoded origin",
            Category:    "encoding",
            BypassType:  "url-encode",
            DangerLevel: "medium",
        },
        
        // Double URL-encoded origin
        {
            Origin: "https%253A%252F%252Fevil.com",
            CustomHeaders: map[string]string{
                "Origin": "https%253A%252F%252Fevil.com",
            },
            Priority:    8,
            Description: "Double URL-encoded origin (decode bypass)",
            Category:    "encoding",
            BypassType:  "double-url-encode",
            DangerLevel: "high",
        },
        
        // Partially encoded origin
        {
            Origin: "https://%65v%69l.com",
            CustomHeaders: map[string]string{
                "Origin": "https://%65v%69l.com",
            },
            Priority:    7,
            Description: "Partially URL-encoded domain letters",
            Category:    "encoding",
            BypassType:  "partial-url-encode",
            DangerLevel: "medium",
        },
        
        // Overlong UTF-8 encoding
        {
            Origin: "https://evil%C0%AEcom",
            CustomHeaders: map[string]string{
                "Origin": "https://evil%C0%AEcom",
            },
            Priority:    8,
            Description: "Overlong UTF-8 encoding of dot",
            Category:    "encoding",
            BypassType:  "overlong-utf8",
            DangerLevel: "high",
        },
        
        // Percent encoding with uppercase hex
        {
            Origin: "https://%45%56%49%4C.com",
            CustomHeaders: map[string]string{
                "Origin": "https://%45%56%49%4C.com",
            },
            Priority:    6,
            Description: "Uppercase percent encoding (EVIL)",
            Category:    "encoding",
            BypassType:  "uppercase-percent",
            DangerLevel: "low",
        },
        
        // Mixed case percent encoding
        {
            Origin: "https://%45v%49l.com",
            CustomHeaders: map[string]string{
                "Origin": "https://%45v%49l.com",
            },
            Priority:    6,
            Description: "Mixed case percent encoding",
            Category:    "encoding",
            BypassType:  "mixed-case-percent",
            DangerLevel: "low",
        },
        
        // Base64 encoded origin (non-standard but tested)
        {
            Origin: "aHR0cHM6Ly9ldmlsLmNvbQ==",
            CustomHeaders: map[string]string{
                "Origin": "aHR0cHM6Ly9ldmlsLmNvbQ==",
            },
            Priority:    4,
            Description: "Base64 encoded origin (non-standard)",
            Category:    "encoding",
            BypassType:  "base64-encode",
            DangerLevel: "low",
        },
        
        // HTML entity encoded origin
        {
            Origin: "https://evil&#46;com",
            CustomHeaders: map[string]string{
                "Origin": "https://evil&#46;com",
            },
            Priority:    6,
            Description: "HTML entity encoded dot",
            Category:    "encoding",
            BypassType:  "html-entity",
            DangerLevel: "medium",
        },
        
        // Unicode escape sequences
        {
            Origin: "https://\\u0065\\u0076\\u0069\\u006c.com",
            CustomHeaders: map[string]string{
                "Origin": "https://\\u0065\\u0076\\u0069\\u006c.com",
            },
            Priority:    6,
            Description: "Unicode escape sequence (JavaScript style)",
            Category:    "encoding",
            BypassType:  "unicode-escape",
            DangerLevel: "medium",
        },
        
        // Hex-encoded ASCII
        {
            Origin: "\\x68\\x74\\x74\\x70\\x73:\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x63\\x6f\\x6d",
            CustomHeaders: map[string]string{
                "Origin": "\\x68\\x74\\x74\\x70\\x73:\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x63\\x6f\\x6d",
            },
            Priority:    5,
            Description: "Hex-encoded ASCII characters",
            Category:    "encoding",
            BypassType:  "hex-ascii",
            DangerLevel: "low",
        },
    }
}

// ============================================================
// CATEGORY 7: BROWSER SPOOFING HEADERS
// ============================================================

func (hg *HeaderGenerator) generateBrowserSpoofingHeaders(origin string) []HeaderSet {
    userAgents := []struct {
        ua         string
        browser    string
        desc       string
        priority   int
    }{
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Chrome-120-Windows",
            "Latest Chrome on Windows 10",
            10,
        },
        {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Safari-17-MacOS",
            "Latest Safari on macOS Sonoma",
            10,
        },
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Firefox-121-Windows",
            "Latest Firefox on Windows 10",
            10,
        },
        {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Edge-120-Windows",
            "Latest Edge on Windows 10",
            9,
        },
        {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Safari-iOS-17",
            "Mobile Safari on iPhone iOS 17",
            9,
        },
        {
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Chrome-Android-14",
            "Chrome on Android 14 (Pixel)",
            9,
        },
        {
            "curl/8.4.0",
            "curl",
            "Command-line curl (common for APIs)",
            7,
        },
        {
            "python-requests/2.31.0",
            "Python-Requests",
            "Python requests library",
            7,
        },
        {
            "Go-http-client/2.0 (GOD-MODE scanner)",
            "Go-Client",
            "Custom Go HTTP client",
            5,
        },
        {
            "",
            "Empty-UA",
            "Empty User-Agent string",
            6,
        },
        {
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
            "IE-8-Windows",
            "Internet Explorer 8 (legacy)",
            6,
        },
        {
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Googlebot",
            "Google search engine crawler",
            8,
        },
        {
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Facebook-Bot",
            "Facebook link preview bot",
            8,
        },
        {
            "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
            "LinkedIn-Bot",
            "LinkedIn crawler",
            7,
        },
        {
            "Twitterbot/1.0",
            "Twitter-Bot",
            "Twitter/X social media bot",
            7,
        },
    }
    
    var variations []HeaderSet
    
    for _, uaInfo := range userAgents {
        headers := map[string]string{
            "Origin": origin,
        }
        
        if uaInfo.ua != "" {
            headers["User-Agent"] = uaInfo.ua
        }
        
        // Add browser-specific headers based on UA
        switch {
        case strings.Contains(uaInfo.browser, "Chrome") || strings.Contains(uaInfo.browser, "Edge"):
            headers["sec-ch-ua"] = `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = `"Windows"`
            
        case strings.Contains(uaInfo.browser, "Safari"):
            headers["sec-ch-ua"] = ""
            
        case strings.Contains(uaInfo.browser, "Firefox"):
            headers["DNT"] = "1"
            headers["TE"] = "Trailers"
            
        case strings.Contains(uaInfo.browser, "Bot"), strings.Contains(uaInfo.browser, "bot"):
            headers["From"] = "bot@example.com"
        }
        
        variations = append(variations, HeaderSet{
            Origin:        origin,
            CustomHeaders: headers,
            Priority:      uaInfo.priority,
            Description:   fmt.Sprintf("UA: %s (%s)", uaInfo.browser, uaInfo.desc),
            Category:      "browser-spoofing",
            BypassType:    "user-agent-spoofing",
            DangerLevel:   "medium",
        })
    }
    
    return variations
}

// ============================================================
// CATEGORY 8: CREDENTIAL & AUTHENTICATION HEADERS
// ============================================================

func (hg *HeaderGenerator) generateCredentialHeaders(origin string) []HeaderSet {
    return []HeaderSet{
        // Standard cookie-based credential test
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Cookie":                    "sessionid=abc123; csrftoken=xyz789",
                "Authorization":            "",
            },
            Priority:    9,
            Description: "Cookie credentials with malicious origin",
            Category:    "credential-test",
            BypassType:  "cookie-theft",
            DangerLevel: "critical",
        },
        
        // Bearer token test
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Authorization":            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            },
            Priority:    9,
            Description: "Bearer token with malicious origin",
            Category:    "credential-test",
            BypassType:  "token-theft",
            DangerLevel: "critical",
        },
        
        // Basic auth test
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Authorization":            "Basic YWRtaW46cGFzc3dvcmQ=",
            },
            Priority:    8,
            Description: "Basic auth credentials exposed",
            Category:    "credential-test",
            BypassType:  "basic-auth-exposure",
            DangerLevel: "high",
        },
        
        // API key in custom header
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "X-API-Key":                "sk-live-abcdef1234567890",
                "X-Auth-Token":             "token_abc123_xyz",
            },
            Priority:    8,
            Description: "API keys in custom headers with malicious origin",
            Category:    "credential-test",
            BypassType:  "api-key-exposure",
            DangerLevel: "high",
        },
        
        // Multiple auth mechanisms simultaneously
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Cookie":                    "session=abc123",
                "Authorization":            "Bearer token123",
                "X-CSRF-Token":             "csrf-token-value",
                "X-Requested-With":         "XMLHttpRequest",
            },
            Priority:    10,
            Description: "Multiple authentication mechanisms exposed",
            Category:    "credential-test",
            BypassType:  "multi-auth-exposure",
            DangerLevel: "critical",
        },
        
        // CSRF token exposure
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "X-CSRF-Token":             "random-csrf-token-value",
                "X-XSRF-Token":             "xsrf-token-value",
            },
            Priority:    8,
            Description: "CSRF tokens accessible cross-origin",
            Category:    "credential-test",
            BypassType:  "csrf-token-leak",
            DangerLevel: "high",
        },
        
        // Session ID in multiple locations
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Cookie":                    "PHPSESSID=session_id_here; JSESSIONID=jsession_value",
                "X-Session-ID":             "session_id_here",
            },
            Priority:    9,
            Description: "Session IDs in cookies and headers",
            Category:    "credential-test",
            BypassType:  "session-hijacking",
            DangerLevel: "critical",
        },
        
        // OAuth tokens
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Authorization":            "OAuth oauth_consumer_key=",
                "X-OAuth-Token":            "oauth_token_value",
            },
            Priority:    8,
            Description: "OAuth token exposure",
            Category:    "credential-test",
            BypassType:  "oauth-token-leak",
            DangerLevel: "high",
        },
        
        // NTLM/Negotiate auth
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Authorization":            "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFAAAADw==",
            },
            Priority:    7,
            Description: "NTLM authentication challenge",
            Category:    "credential-test",
            BypassType:  "ntlm-auth",
            DangerLevel: "medium",
        },
        
        // AWS-style auth headers
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "X-Amz-Security-Token":      "very-long-aws-security-token...",
                "X-Amz-Date":                "20240115T120000Z",
            },
            Priority:    7,
            Description: "AWS-style authentication headers",
            Category:    "credential-test",
            BypassType:  "cloud-cred-exposure",
            DangerLevel: "high",
        },
        
        // Empty credentials (testing if server accepts)
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                    origin,
                "Cookie":                    "",
                "Authorization":            "",
            },
            Priority:    5,
            Description: "Empty credential headers (acceptance test)",
            Category:    "credential-test",
            BypassType:  "empty-credentials",
            DangerLevel: "low",
        },
    }
}

// ============================================================
// CATEGORY 9: PREFLIGHT (OPTIONS) SPECIFIC HEADERS
// ============================================================

func (hg *HeaderGenerator) generatePreflightHeaders(origin string) []HeaderSet {
    methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
    customMethods := []string{"ADMIN", "DEBUG", "EXECUTE", "UPLOAD", "IMPORT", "EXPORT"}
    
    var variations []HeaderSet
    
    // Test each method individually
    for _, method := range methods {
        variations = append(variations, HeaderSet{
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                         origin,
                "Access-Control-Request-Method":  method,
            },
            Priority:    6,
            Description: fmt.Sprintf("Preflight for %s method", method),
            Category:    "preflight",
            BypassType:  "method-enumeration",
            DangerLevel: func() string {
                if method == "DELETE" || method == "TRACE" || method == "CONNECT" {
                    return "high"
                }
                return "medium"
            }(),
        })
    }
    
    // Custom/non-standard methods
    for _, method := range customMethods {
        variations = append(variations, HeaderSet{
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                         origin,
                "Access-Control-Request-Method":  method,
            },
            Priority:    7,
            Description: fmt.Sprintf("Preflight for custom method: %s", method),
            Category:    "preflight",
            BypassType:  "custom-method",
            DangerLevel: "high",
        })
    }
    
    // Dangerous header combinations
    dangerousHeaders := [][]string{
        {"Authorization", "Content-Type"},
        {"X-Auth-Token", "X-API-Key"},
        {"Cookie", "Set-Cookie"},
        {"X-Forwarded-For", "X-Original-URL"},
        {"*"},  // Wildcard
    }
    
    for _, headerCombo := range dangerousHeaders {
        headers := map[string]string{
            "Origin":                         origin,
            "Access-Control-Request-Method":  "POST",
        }
        
        if len(headerCombo) == 1 && headerCombo[0] == "*" {
            headers["Access-Control-Request-Headers"] = "*"
        } else {
            headers["Access-Control-Request-Headers"] = strings.Join(headerCombo, ", ")
        }
        
        variations = append(variations, HeaderSet{
            Origin:        origin,
            CustomHeaders: headers,
            Priority:      8,
            Description:   fmt.Sprintf("Preflight requesting sensitive headers: %v", headerCombo),
            Category:      "preflight",
            BypassType:    "dangerous-headers",
            DangerLevel:   "high",
        })
    }
    
    // Method override via preflight
    variations = append(variations, HeaderSet{
        Origin: origin,
        CustomHeaders: map[string]string{
            "Origin":                         origin,
            "Access-Control-Request-Method":  "POST",
            "Access-Control-Request-Headers": "X-HTTP-Method-Override, X-Method-Override",
        },
        Priority:    9,
        Description: "Preflight with method override headers",
        Category:    "preflight",
        BypassType:  "method-override",
        DangerLevel: "critical",
    })
    
    // Cache manipulation preflight
    variations = append(variations, HeaderSet{
        Origin: origin,
        CustomHeaders: map[string]string{
            "Origin":                         origin,
            "Access-Control-Request-Method":  "GET",
            "Access-Control-Max-Age":         "86400",
        },
        Priority:    6,
        Description: "Preflight attempting cache duration extension",
        Category:    "preflight",
        BypassType:  "cache-poisoning",
        DangerLevel: "medium",
    })
    
    // Private network preflight (newer browsers)
    variations = append(variations, []HeaderSet{
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                              origin,
                "Access-Control-Request-Method":       "GET",
                "Access-Control-Request-Private-Network": "true",
            },
            Priority:    7,
            Description: "Private network access preflight",
            Category:    "preflight",
            BypassType:  "private-network-access",
            DangerLevel: "high",
        },
        {
            Origin: origin,
            CustomHeaders: map[string]string{
                "Origin":                                origin,
                "Access-Control-Request-Method":         "GET",
                "Access-Control-Request-Private-Network": "true",
                "Access-Control-Request-Headers":        "X-Private-Network-Token",
            },
            Priority:    8,
            Description: "Private network with custom headers",
            Category:    "preflight",
            BypassType:  "private-network-access",
            DangerLevel: "critical",
        },
    }...)
    
    return variations
}

// ============================================================
// CATEGORY 10: ADVANCED BYPASS COMBINATIONS
// ============================================================

func (hg *HeaderGenerator) generateAdvancedBypassCombinations(origin string, targetURL string) []HeaderSet {
	_ = origin
    targetDomain := extractDomainFromURL(targetURL)
    
    return []HeaderSet{
        // Combination: Backslash + IP spoofing
        {
            Origin: fmt.Sprintf("https://evil.com\\%s", targetDomain),
            CustomHeaders: map[string]string{
                "Origin":          fmt.Sprintf("https://evil.com\\%s", targetDomain),
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP":       "127.0.0.1",
            },
            Priority:    10,
            Description: "Combined: Backslash bypass + internal IP spoofing",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: @ symbol + Host header override
        {
            Origin: fmt.Sprintf("https://evil.com@%s", targetDomain),
            CustomHeaders: map[string]string{
                "Origin":          fmt.Sprintf("https://evil.com@%s", targetDomain),
                "Host":            "evil.com",
            },
            Priority:    10,
            Description: "Combined: @ symbol bypass + Host header confusion",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Null byte + CRLF
        {
            Origin: "https://evil.com%00\r\nX-Forwarded-Host: evil.com",
            CustomHeaders: map[string]string{
                "Origin": "https://evil.com%00\r\nX-Forwarded-Host: evil.com",
            },
            Priority:    10,
            Description: "Combined: Null byte + CRLF injection",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Unicode + Referer spoofing
        {
            Origin: "https://еvіl.com",  // Cyrillic
            CustomHeaders: map[string]string{
                "Origin":  "https://еvіl.com",
                "Referer": "https://еvіl.com/page",
            },
            Priority:    9,
            Description: "Combined: Unicode homograph + matching Referer",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Double encode + Cookie theft
        {
            Origin: "https%253A%252F%252Fevil.com",
            CustomHeaders: map[string]string{
                "Origin":                    "https%253A%252F%252Fevil.com",
                "Cookie":                    "session=secret",
                "X-Forwarded-Proto":         "https",
            },
            Priority:    9,
            Description: "Combined: Double encoding + credentials + proto spoof",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Tab injection + Method override
        {
            Origin: "https://evil.com\t@" + targetDomain,
            CustomHeaders: map[string]string{
                "Origin":                "https://evil.com\t@" + targetDomain,
                "X-HTTP-Method-Override": "DELETE",
                "X-Method-Override":     "ADMIN",
            },
            Priority:    10,
            Description: "Combined: Tab injection + method override",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Full-width + Bot UA
        {
            Origin: "https://ｅｖｉｌ.com",
            CustomHeaders: map[string]string{
                "Origin":      "https://ｅｖｉｌ.com",
                "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "From":        "googlebot@google.com",
            },
            Priority:    9,
            Description: "Combined: Full-width spoof + Googlebot impersonation",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // Combination: Fragment bypass + Credentials
        {
            Origin: "https://evil.com#" + targetDomain,
            CustomHeaders: map[string]string{
                "Origin":                    "https://evil.com#" + targetDomain,
                "Authorization":            "Bearer secret_token_12345",
                "X-Requested-With":         "XMLHttpRequest",
            },
            Priority:    9,
            Description: "Combined: Fragment bypass + AJAX credentials",
            Category:    "advanced-combo",
            BypassType:  "multi-vector",
            DangerLevel: "critical",
        },
        
        // DNS rebinding preparation + Internal headers
        {
            Origin: "https://7f000001.rbndr.us",
            CustomHeaders: map[string]string{
                "Origin":          "https://7f000001.rbndr.us",
                "X-Forwarded-For": "169.254.169.254",  // AWS metadata
                "Metadata-True":   "true",
            },
            Priority:    10,
            Description: "Combined: DNS rebinding + cloud metadata access",
            Category:    "advanced-combo",
            BypassType:  "ssrf-preparation",
            DangerLevel: "critical",
        },
        
        // Prefix bypass + Subdomain takeover prep
        {
            Origin: fmt.Sprintf("https://%s.evil.com", targetDomain),
            CustomHeaders: map[string]string{
                "Origin":          fmt.Sprintf("https://%s.evil.com", targetDomain),
                "Host":            targetDomain,
                "X-Forwarded-Host": fmt.Sprintf("%s.evil.com", targetDomain),
            },
            Priority:    9,
            Description: "Combined: Subdomain prefix + Host confusion (takeover prep)",
            Category:    "advanced-combo",
            BypassType:  "subdomain-takeover-prep",
            DangerLevel: "critical",
        },
    }
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

// GetHighPriorityHeaders returns only the most effective header sets
func (hg *HeaderGenerator) GetHighPriorityHeaders(minPriority int, origin string, targetURL string) []HeaderSet {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    var highPriority []HeaderSet
    for _, headerSet := range allHeaders {
        if headerSet.Priority >= minPriority {
            highPriority = append(highPriority, headerSet)
        }
    }
    
    return highPriority
}

// GetHeadersByCategory returns headers filtered by category
func (hg *HeaderGenerator) GetHeadersByCategory(category string, origin string, targetURL string) []HeaderSet {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    var filtered []HeaderSet
    for _, headerSet := range allHeaders {
        if headerSet.Category == category {
            filtered = append(filtered, headerSet)
        }
    }
    
    return filtered
}

// GetHeadersByBypassType returns headers for specific bypass type
func (hg *HeaderGenerator) GetHeadersByBypassType(bypassType string, origin string, targetURL string) []HeaderSet {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    var filtered []HeaderSet
    for _, headerSet := range allHeaders {
        if headerSet.BypassType == bypassType {
            filtered = append(filtered, headerSet)
        }
    }
    
    return filtered
}

// GetCriticalDangerHeaders returns only critical/high danger level headers
func (hg *HeaderGenerator) GetCriticalDangerHeaders(origin string, targetURL string) []HeaderSet {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    var critical []HeaderSet
    for _, headerSet := range allHeaders {
        if headerSet.DangerLevel == "critical" || headerSet.DangerLevel == "high" {
            critical = append(critical, headerSet)
        }
    }
    
    return critical
}

// RandomHeaderSet returns a random header set from the generated pool
func (hg *HeaderGenerator) RandomHeaderSet(origin string, targetURL string) HeaderSet {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    if len(allHeaders) == 0 {
        return HeaderSet{}
    }
    
    return allHeaders[hg.randSource.Intn(len(allHeaders))]
}

// GenerateStatistics provides metadata about generated headers
func (hg *HeaderGenerator) GenerateStatistics(origin string, targetURL string) HeaderStats {
    allHeaders := hg.GenerateAllHeaderVariations(origin, targetURL)
    
    stats := HeaderStats{
        TotalHeaderSets: len(allHeaders),
        ByCategory:      make(map[string]int),
        ByBypassType:    make(map[string]int),
        ByDangerLevel:   make(map[string]int),
        AvgPriority:     0,
    }
    
    totalPriority := 0
    
    for _, hs := range allHeaders {
        stats.ByCategory[hs.Category]++
        stats.ByBypassType[hs.BypassType]++
        stats.ByDangerLevel[hs.DangerLevel]++
        totalPriority += hs.Priority
        
        if hs.Priority > stats.MaxPriority {
            stats.MaxPriority = hs.Priority
        }
    }
    
    if len(allHeaders) > 0 {
        stats.AvgPriority = float64(totalPriority) / float64(len(allHeaders))
    }
    
    return stats
}

// HeaderStats contains statistics about generated header sets
type HeaderStats struct {
    TotalHeaderSets int               `json:"total_header_sets"`
    ByCategory      map[string]int    `json:"by_category"`
    ByBypassType    map[string]int    `json:"by_bypass_type"`
    ByDangerLevel   map[string]int    `json:"by_danger_level"`
    AvgPriority     float64           `json:"avg_priority"`
    MaxPriority     int               `json:"max_priority"`
}

// PrintSummary outputs human-readable statistics
func (stats HeaderStats) PrintSummary() {
    fmt.Printf("\n📊 Header Generation Statistics")
    fmt.Printf("\n%s\n", strings.Repeat("─", 50))
    fmt.Printf("Total Header Sets Generated: %d\n", stats.TotalHeaderSets)
    fmt.Printf("Average Priority: %.1f/10\n", stats.AvgPriority)
    fmt.Printf("Max Priority: %d/10\n", stats.MaxPriority)
    
    fmt.Printf("\n📁 By Category:\n")
    for cat, count := range stats.ByCategory {
        fmt.Printf("  • %-25s : %d\n", cat, count)
    }
    
    fmt.Printf("\n🎯 By Bypass Type:\n")
    for bt, count := range stats.ByBypassType {
        fmt.Printf("  • %-30s : %d\n", bt, count)
    }
    
    fmt.Printf("\n⚠️  By Danger Level:\n")
    for dl, count := range stats.ByDangerLevel {
        fmt.Printf("  • %-12s : %d\n", dl, count)
    }
    fmt.Println()
}

// Helper function to extract domain from URL
func extractDomainFromURL(rawURL string) string {
    // Simple extraction (in real code, use net/url)
    if strings.HasPrefix(rawURL, "https://") {
        rawURL = strings.TrimPrefix(rawURL, "https://")
    } else if strings.HasPrefix(rawURL, "http://") {
        rawURL = strings.TrimPrefix(rawURL, "http://")
    }
    
    if idx := strings.Index(rawURL, "/"); idx != -1 {
        rawURL = rawURL[:idx]
    }
    if idx := strings.Index(rawURL, ":"); idx != -1 {
        rawURL = rawURL[:idx]
    }
    
    return rawURL
}