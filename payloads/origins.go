package payloads

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Generator struct {
	customOrigins []string
}

func NewGenerator() *Generator {
	return &Generator{
		customOrigins: make([]string, 0),
	}
}

func (g *Generator) GenerateAdvancedOrigins(targetURL string) []string {
	var origins []string

	targetDomain := extractDomain(targetURL)

	// Category 1: Common Attacker Domains
	origins = append(origins, g.commonAttackerDomains()...)

	// Category 2: Target-Specific Variations
	origins = append(origins, g.targetSpecificVariations(targetDomain)...)

	// Category 3: Protocol Variations
	origins = append(origins, g.protocolVariations(targetDomain)...)

	// Category 4: Special Characters & Encoding
	origins = append(origins, g.specialCharacterOrigins(targetDomain)...)

	// Category 5: Subdomain Attacks
	origins = append(origins, g.subdomainAttackOrigins(targetDomain)...)

	// Category 6: Suffix/Prefix Bypass
	origins = append(origins, g.suffixPrefixBypassOrigins(targetDomain)...)

	// Category 7: Unicode & Internationalization
	origins = append(origins, g.unicodeOrigins(targetDomain)...)

	// Category 8: Port Variations
	origins = append(origins, g.portVariations(targetDomain)...)

	// Category 9: Authentication Bypass
	origins = append(origins, g.authBypassOrigins(targetDomain)...)

	// Category 10: Edge Cases
	origins = append(origins, g.EdgeCaseOrigins()...)

	return origins
}

func (g *Generator) commonAttackerDomains() []string {
	return []string{
		"https://evil.com",
		"http://evil.com",
		"https://www.evil.com",
		"http://www.evil.com",
		"https://attacker.com",
		"http://attacker.com",
		"https://malicious.com",
		"http://malicious.com",
		"https://hack.er",
		"http://hack.er",
		"https://example.com",
		"http://example.com",
		"https://sub.evil.com",
		"https://evil.org",
		"https://evil.net",
		"https://evil.io",
		"https://attacker.net",
		"https://malicious.org",
	}
}

func (g *Generator) targetSpecificVariations(domain string) []string {
	return []string{
		fmt.Sprintf("https://%s.evil.com", domain),
		fmt.Sprintf("https://%s.attacker.com", domain),
		fmt.Sprintf("https://evil.%s", domain),
		fmt.Sprintf("https://attacker.%s", domain),
		fmt.Sprintf("https://%s.com.evil.com", domain),
		fmt.Sprintf("https://%s-evil.com", domain),
		fmt.Sprintf("https://%s_evil.com", domain),
		fmt.Sprintf("https://evil-%s.com", domain),
		fmt.Sprintf("https://evilsite.%s", domain),
		fmt.Sprintf("https://%shack.com", domain),
	}
}

func (g *Generator) protocolVariations(domain string) []string {
	return []string{
		fmt.Sprintf("//%s", domain),
		fmt.Sprintf("https://%s/", domain),
		fmt.Sprintf("https://%s#", domain),
		fmt.Sprintf("https://%s/.evil.com", domain),
		fmt.Sprintf("https://%s?.evil.com", domain),
		fmt.Sprintf("HTTPS://%s", domain),
		fmt.Sprintf("HtTpS://%s", domain),
		fmt.Sprintf("\nhttps://%s", domain),
		fmt.Sprintf(" https://%s", domain),
	}
}

func (g *Generator) specialCharacterOrigins(domain string) []string {
	return []string{
		fmt.Sprintf("https://%s%%00.evil.com", domain),
		fmt.Sprintf("https://%s%%0d.evil.com", domain),
		fmt.Sprintf("https://%s%%0a.evil.com", domain),
		fmt.Sprintf("https://%s\t.evil.com", domain),
		fmt.Sprintf("https://%s.evil.com/", domain),
		fmt.Sprintf("https://%s/.evil.com/path", domain),
		fmt.Sprintf("https://%s;@evil.com", domain),
		fmt.Sprintf("https://%s:\\evil.com", domain),
		fmt.Sprintf("https://%s@evil.com", domain),
		fmt.Sprintf("https://%s%%40evil.com", domain),
	}
}

func (g *Generator) subdomainAttackOrigins(domain string) []string {
	return []string{
		fmt.Sprintf("https://_%s.evil.com", domain),
		fmt.Sprintf("https://-%s.evil.com", domain),
		fmt.Sprintf("https://%s..evil.com", domain),
		fmt.Sprintf("https://.%s.evil.com", domain),
		fmt.Sprintf("https://%s.evil.com.evil.com", domain),
		fmt.Sprintf("https://%s%%.evil.com", domain),
		fmt.Sprintf("https://0x%s.evil.com", domain),
	}
}

func (g *Generator) suffixPrefixBypassOrigins(domain string) []string {
	return []string{
		fmt.Sprintf("https://evil%s.com", domain),
		fmt.Sprintf("https://%sevil.com", domain),
		fmt.Sprintf("https://evil-%s.com", domain),
		fmt.Sprintf("https://%s-evil.com", domain),
		fmt.Sprintf("https://evil.%s.com", domain),
		fmt.Sprintf("https://%s.evil.com", domain),
	}
}

func (g *Generator) unicodeOrigins(domain string) []string {
	return []string{
		fmt.Sprintf("https://ｅｖｉｌ.%s.com", domain), // Full-width characters
		fmt.Sprintf("https://êṽïļ.%s.com", domain), // Accented characters
		fmt.Sprintf("https://𝗲𝘃𝗶𝗹.%s.com", domain), // Mathematical bold
		"https://ｅｖｉｌ.com",            // Full-width evil.com
		"https://evil．com",            // Full-width dot
	}
}

func (g *Generator) portVariations(domain string) []string {
	ports := []string{"80", "443", "8080", "8443", "3000", "5000", "8888"}
	var origins []string

	for _, port := range ports {
		origins = append(origins, fmt.Sprintf("https://evil.com:%s", port))
		origins = append(origins, fmt.Sprintf("https://%s:%s", domain, port))
	}

	return origins
}

func (g *Generator) authBypassOrigins(domain string) []string {
	return []string{
		fmt.Sprintf("https://evil.com@%s", domain),
		fmt.Sprintf("https://evil.com:%s@%s", "password", domain),
		fmt.Sprintf("https://%s@evil.com", domain),
		fmt.Sprintf("https://evil.com\\@%s", domain),
		fmt.Sprintf("https://evil.com/@/%s", domain),
		fmt.Sprintf("https://evil.com/\\@%s", domain),
		fmt.Sprintf("https://evil.com#@%s", domain),
		fmt.Sprintf("https://evil.com?@%s", domain),
		fmt.Sprintf("https://evil.com#@/%s", domain),
	}
}

func (g *Generator) EdgeCaseOrigins() []string {
	return []string{
		"null",
		"NULL",
		"Null",
		"",
		" ",
		"  ",
		"*",
		"*.evil.com",
		"https://*",
		"http://*",
		"file://",
		"javascript:",
		"data:",
		"data:text/html,<h1>test</h1>",
		"javascript:alert(1)",
		"https://localhost",
		"http://127.0.0.1",
		"https://0x7f000001",
		"https://017700000001",
		"https://2130706433",
		"https://0x7f.1",
		"https://127.1",
		"https://0",
		"https://127.0.0.0",
		"https://0.0.0.0",
		"https://[::]",
		"https://[::1]",
		"https://[0:0:0:0:0:0:0:1]",
	}
}

// Generate Null Byte Injection Payloads
func (g *Generator) GenerateNullBytePayloads(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://evil.com%%00%s", domain),
		fmt.Sprintf("https://evil.com\x00%s", domain),
		fmt.Sprintf("https://evil.com%s\x00", domain),
		fmt.Sprintf("https://evil.com%s%%00", domain),
		fmt.Sprintf("https://evil.com%%00https://%s", domain),
		fmt.Sprintf("https://evil.com\x00https://%s", domain),
		"https://evil.com\x00",
		"https://evil.com%00",
		"https://evil.com%00@evil.com",
		"https://evil.com\x00@evil.com",
		"null\x00https://evil.com",
		"null%00https://evil.com",
		"https://evil.com/\x00/",
		"https://evil.com/%00/",
		"https://evil.com/\x00/..;/",
		"https://evil.com/%00/..;/",
	}
}

// Generate Underscore Subdomain Origins
func (g *Generator) GenerateUnderscoreSubdomainOrigins(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://_%s.evil.com", domain),
		fmt.Sprintf("https://_.%s", domain),
		fmt.Sprintf("https://_.evil.%s", domain),
		fmt.Sprintf("https://_evil.%s", domain),
		fmt.Sprintf("https://_.%s.evil.com", domain),
	}
}

// Generate Case Variations
func (g *Generator) GenerateCaseVariations(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://%s", strings.ToUpper(domain)),
		fmt.Sprintf("https://%s", mixCase(domain)),
		fmt.Sprintf("https://%s", alternateCase(domain)),
		fmt.Sprintf("httPS://%s", domain),
		fmt.Sprintf("HTTps://%s", domain),
		fmt.Sprintf("HTTPS://%s", domain),
		fmt.Sprintf("https://%s/PATH", domain),
		fmt.Sprintf("https://%s/path", strings.ToUpper(domain)),
	}
}

// Generate URL Encoded Origins
func (g *Generator) GenerateURLEncodedOrigins(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://%s", url.PathEscape(domain)),
		fmt.Sprintf("https://%s", doubleEncode(domain)),
		fmt.Sprintf("https://%%65%%76%%69%%6c.com"), // evil.com encoded
		fmt.Sprintf("https://%s%%2eevil.com", domain),
		fmt.Sprintf("https://%s%%2eevil%%2ecom", domain),
		fmt.Sprintf("https://%s.evil.com%%00", domain),
		fmt.Sprintf("https://%s.evil.com%%01", domain),
		fmt.Sprintf("https://%s.evil.com%%02", domain),
	}
}

// Generate Backslash Bypass Origins
func (g *Generator) GenerateBackslashBypassOrigins(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://evil.com\\%s", domain),
		fmt.Sprintf("https://evil.com/%%5c%s", domain),
		fmt.Sprintf("https://evil.com\\\\%s", domain),
		fmt.Sprintf("https://evil.com/%s/\\.evil.com", domain),
		fmt.Sprintf("https://evil.com/%s/..\\/", domain),
		fmt.Sprintf("https://evil.com/%s/..%%5c/", domain),
	}
}

// Generate @ Symbol Bypass Origins
func (g *Generator) GenerateAtSymbolBypassOrigins(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://evil.com@%s", domain),
		fmt.Sprintf("https://evil.com@@%s", domain),
		fmt.Sprintf("https://evil.com:@%s", domain),
		fmt.Sprintf("https://evil.com:pass@%s", domain),
		fmt.Sprintf("https://evil.com@%s@evil.com", domain),
		fmt.Sprintf("https://evil.com@/%%40%s", domain),
		fmt.Sprintf("https://evil.com/@/%s", domain),
		fmt.Sprintf("https://evil.com\\@%s", domain),
		fmt.Sprintf("https://evil.com/\\@/%s", domain),
	}
}

// Generate Fragment Bypass Origins
func (g *Generator) GenerateFragmentBypassOrigins(targetURL string) []string {
	domain := extractDomain(targetURL)

	return []string{
		fmt.Sprintf("https://evil.com#%s", domain),
		fmt.Sprintf("https://evil.com/#%s", domain),
		fmt.Sprintf("https://evil.com/?#%s", domain),
		fmt.Sprintf("https://evil.com/%%23%s", domain),
		fmt.Sprintf("https://%s.evil.com#%s", domain, domain),
		fmt.Sprintf("https://%s#evil.com", domain),
	}
}

// Generate DNS Rebinding Origins
func (g *Generator) GenerateDNSRebindingOrigins() []string {
	return []string{
		"https://7f000001.rbndr.us",
		"https://127.0.0.1.nip.io",
		"https://localhost.sb",
		"https://1.2.3.4.nip.io",
		"https://169.254.169.254.nip.io", // AWS metadata
		"https://metadata.google.internal.nip.io",
		"https://7f000001.xip.io",
		"https://vcap.me",      // Resolves to 127.0.0.1
		"https://localtest.me", // Resolves to 127.0.0.1
		"https://lvh.me",       // Resolves to 127.0.0.1
		"https://spoofed.local",
	}
}

// Load custom origins from file
func (g *Generator) LoadFromFile(filepath string) []string {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return []string{}
	}

	var origins []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		origins = append(origins, line)
	}

	return origins
}

// Helper functions
func extractDomain(targetURL string) string {
	targetURL = strings.TrimSpace(targetURL)
	if !strings.HasPrefix(strings.ToLower(targetURL), "http://") && !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		targetURL = "https://" + targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	hostname := u.Hostname()
	if hostname == "" {
		return targetURL
	}

	if net.ParseIP(hostname) != nil {
		return hostname
	}

	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return hostname
}

func mixCase(s string) string {
	result := ""
	for i, c := range s {
		if i%2 == 0 {
			result += strings.ToUpper(string(c))
		} else {
			result += strings.ToLower(string(c))
		}
	}
	return result
}

func alternateCase(s string) string {
	result := ""
	upper := true
	for _, c := range s {
		if upper {
			result += strings.ToUpper(string(c))
		} else {
			result += string(c)
		}
		upper = !upper
	}
	return result
}

func doubleEncode(s string) string {
	first := url.PathEscape(s)
	return url.PathEscape(first)
}
