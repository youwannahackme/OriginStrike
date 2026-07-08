package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/youwannahackme/originstrike/core"

	"github.com/fatih/color"
)

type OutputFormatter struct {
	useColor bool
	verbose  bool
	silent   bool
	writer   *tabwriter.Writer
}

func NewOutputFormatter(useColor, verbose, silent bool) *OutputFormatter {
	return &OutputFormatter{
		useColor: useColor,
		verbose:  verbose,
		silent:   silent,
		writer:   tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0),
	}
}

// PrintBanner prints the awesome ASCII banner
func PrintBanner(version, author string) {
	banner := `
 ╔═════════════════════════════════════════════════════════════════════════════════════════╗
 ║                                                                                         ║
 ║   ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗   ║
 ║  ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝   ║
 ║  ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗     ║
 ║  ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝     ║
 ║  ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗   ║
 ║   ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝   ║
 ║                                                                                         ║
 ║                         🔥 ULTIMATE CORS EXPLOITATION SUITE 🔥                          ║
 ║                               Version %s | Author: %s                                  ║
 ║                            [ZERO FALSE POSITIVES - GOD MODE]                            ║
 ╚═════════════════════════════════════════════════════════════════════════════════════════╝
`
	if !color.NoColor {
		color.Cyan(banner, version, author)
	} else {
		fmt.Printf(banner, version, author)
	}
}

// PrintScanStart prints scanning initialization message
func (of *OutputFormatter) PrintScanStart(targetCount int, concurrency int) {
	if of.silent {
		return
	}

	color.Cyan("\n[★] Initializing Advanced CORS Scanning Engine...")
	color.White("    ├─ Targets to Scan: %d", targetCount)
	color.White("    ├─ Concurrency Level: %d", concurrency)
	color.White("    └─ Detection Mode: ZERO FALSE POSITIVE\n")
}

// PrintScanningURL prints current URL being scanned
func (of *OutputFormatter) PrintScanningURL(url string, index int, total int) {
	if of.silent || !of.verbose {
		return
	}

	progress := float64(index) / float64(total) * 100
	color.Yellow("[%3.1f%%] Scanning: %s", progress, url)
}

// PrintVulnerabilityFound prints vulnerability details
func (of *OutputFormatter) PrintVulnerabilityFound(result *core.ScanResult) {
	if of.silent {
		return
	}

	color.Red("\n[!] ⚠️  VULNERABILITY DETECTED!")
	color.White("┌─────────────────────────────────────────────────────────────")
	color.Red("│ 🎯 Target:      %s", result.URL)
	color.Red("│ 🔓 Origin:      %s", result.Origin)
	color.Red("│ 💀 Severity:    %s", GetSeverityWithColor(result.Severity))
	color.Red("│ 📝 Type:        %s", result.VulnType)
	color.Red("│ ✅ Confidence:  %.1f%%", result.Confidence)

	if result.BypassTechnique != "" {
		color.Magenta("│ 🛠️  Bypass:      %s", result.BypassTechnique)
	}

	color.White("├─────────────────────────────────────────────────────────────")

	if result.POC != "" && of.verbose {
		color.Green("│ 📄 Proof of Concept:")
		pocLines := strings.Split(result.POC, "\n")
		for _, line := range pocLines[:min(len(pocLines), 10)] { // Limit POC display
			color.White("│   %s", line)
		}
	}

	if result.Remediation != "" {
		color.Cyan("│ 🔧 Remediation: %s", result.Remediation)
	}

	color.White("└─────────────────────────────────────────────────────────────")
}

// PrintScanSummary prints final scan statistics
func (of *OutputFormatter) PrintScanSummary(stats *core.ScanStats, results []*core.ScanResult, duration time.Duration) {
	if of.silent {
		return
	}

	vulnCount := len(results)

	color.Cyan("\n" + strings.Repeat("═", 70))
	color.Cyan("                    📊 SCAN SUMMARY REPORT")
	color.Cyan(strings.Repeat("═", 70))

	color.White("\n⏱️  Scan Duration:     %v", duration.Round(time.Millisecond))
	color.White("🎯 Total URLs:        %d", stats.TotalURLs)
	color.White("✅ Scanned:           %d", stats.ScannedURLs)
	color.White("🔴 Vulnerabilities:   %d", vulnCount)
	color.White("📤 Requests Sent:     %d", stats.TotalRequests)
	color.White("🧪 Origins Tested:    %d", stats.TotalOriginsTested)

	// Severity breakdown
	critical := countBySeverity(results, "CRITICAL")
	high := countBySeverity(results, "HIGH")
	medium := countBySeverity(results, "MEDIUM")
	low := countBySeverity(results, "LOW")
	info := countBySeverity(results, "INFO")

	color.White("\n📈 Severity Breakdown:")
	if critical > 0 {
		color.Red("    ☠️  CRITICAL:  %d", critical)
	}
	if high > 0 {
		color.Red("    🔴 HIGH:      %d", high)
	}
	if medium > 0 {
		color.Yellow("    🟡 MEDIUM:    %d", medium)
	}
	if low > 0 {
		color.Green("    🟢 LOW:       %d", low)
	}
	if info > 0 {
		color.Cyan("    🔵 INFO:      %d", info)
	}

	color.Cyan("\n" + strings.Repeat("═", 70))
}

// PrintTableResults prints results in table format
func (of *OutputFormatter) PrintTableResults(results []*core.ScanResult) {
	if of.silent || len(results) == 0 {
		return
	}

	color.Cyan("\n📋 VULNERABILITY TABLE:\n")

	fmt.Fprintf(of.writer, "SEVERITY\tTYPE\tORIGIN\tURL\n")
	fmt.Fprintf(of.writer, "--------\t----\t------\t---\n")

	for _, r := range results {
		fmt.Fprintf(of.writer, "%s\t%s\t%s\t%s\n",
			r.Severity,
			TruncateString(r.VulnType, 25),
			TruncateString(r.Origin, 30),
			TruncateString(r.URL, 50),
		)
	}

	of.writer.Flush()
}

// ExportToJSON exports results to JSON file
func ExportToJSON(filepath string, results []*core.ScanResult, stats *core.ScanStats) error {
	type Report struct {
		Metadata        Metadata           `json:"metadata"`
		Statistics      *core.ScanStats    `json:"statistics"`
		Vulnerabilities []*core.ScanResult `json:"vulnerabilities"`
	}

	report := Report{
		Metadata: Metadata{
			ScannerName: "OriginStrike",
			Version:     "2.0-GOD-MODE",
			Timestamp:   time.Now().Format(time.RFC3339),
			Author:      "whoami_404",
		},
		Statistics:      stats,
		Vulnerabilities: results,
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	err = os.WriteFile(filepath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	color.Green("[✓] JSON report saved to: %s", filepath)
	return nil
}

// ExportToCSV exports results to CSV format
func ExportToCSV(filepath string, results []*core.ScanResult) error {
	var csvContent strings.Builder

	// Header
	csvContent.WriteString("ID,URL,Origin,Method,Status,StatusCode,Severity,VulnType,Title,Confidence,BypassTechnique,Timestamp\n")

	// Data rows
	for _, r := range results {
		csvContent.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%d,%s,%s,%s,%.1f,%s,%s\n",
			EscapeCSV(r.ID),
			EscapeCSV(r.URL),
			EscapeCSV(r.Origin),
			EscapeCSV(r.Method),
			EscapeCSV(r.Status),
			r.StatusCode,
			EscapeCSV(r.Severity),
			EscapeCSV(r.VulnType),
			EscapeCSV(r.Title),
			r.Confidence,
			EscapeCSV(r.BypassTechnique),
			r.Timestamp.Format(time.RFC3339),
		))
	}

	err := os.WriteFile(filepath, []byte(csvContent.String()), 0644)
	if err != nil {
		return fmt.Errorf("failed to write CSV: %w", err)
	}

	color.Green("[✓] CSV report saved to: %s", filepath)
	return nil
}

// ExportToHTML generates comprehensive HTML report
func ExportToHTML(filepath string, results []*core.ScanResult, stats *core.ScanStats) error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OriginStrike Security Report</title>
    <style>
        :root {
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #16a34a;
            --bg-dark: #1e293b;
            --bg-light: #f8fafc;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8fafc;
        }
        
        .stat-card {
            background: white;
            padding: 24px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-label {
            color: #64748b;
            margin-top: 8px;
            font-size: 0.9em;
        }
        
        .results-section {
            padding: 40px;
        }
        
        .section-title {
            font-size: 1.8em;
            color: var(--bg-dark);
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .vuln-card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .severity-critical { border-left: 4px solid #dc2626; }
        .severity-high { border-left: 4px solid #ea580c; }
        .severity-medium { border-left: 4px solid #d97706; }
        .severity-low { border-left: 4px solid #16a34a; }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .badge-critical { background: #fef2f2; color: #dc2626; }
        .badge-high { background: #fff7ed; color: #ea580c; }
        .badge-medium { background: #fffbeb; color: #d97706; }
        .badge-low { background: #f0fdf4; color: #16a34a; }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }
        
        .vuln-title {
            font-size: 1.2em;
            font-weight: 600;
            color: var(--bg-dark);
        }
        
        .vuln-details {
            display: grid;
            gap: 12px;
            color: #475569;
        }
        
        .detail-row {
            display: flex;
            gap: 8px;
        }
        
        .detail-label {
            font-weight: 600;
            min-width: 120px;
            color: #64748b;
        }
        
        .poc-box {
            background: #1e293b;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin-top: 12px;
        }
        
        .remediation-box {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 16px;
            border-radius: 8px;
            margin-top: 12px;
        }
        
        .footer {
            background: var(--bg-dark);
            color: white;
            text-align: center;
            padding: 24px;
            font-size: 0.9em;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 OriginStrike Security Report</h1>
            <div class="subtitle">Advanced CORS Vulnerability Assessment</div>
            <div class="subtitle" style="margin-top: 8px;">Generated: %s</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Total URLs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Requests Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Origins Tested</div>
            </div>
        </div>
        
        <div class="results-section">
            <h2 class="section-title">🎯 Vulnerabilities Detected</h2>
            %s
        </div>
        
        <div class="footer">
            <p>Generated by OriginStrike v2.0 (GOD MODE) | Zero False Positive Guarantee</p>
            <p style="margin-top: 8px;">© whoami_404 | For Authorized Testing Only</p>
        </div>
    </div>
</body>
</html>`

	// Generate vulnerability cards HTML
	var vulnCardsHTML strings.Builder

	for i, r := range results {
		severityClass := getSeverityClass(r.Severity)
		badgeClass := getBadgeClass(r.Severity)

		pocDisplay := ""
		if r.POC != "" {
			pocDisplay = fmt.Sprintf(`<div class="poc-box"><strong>Proof of Concept:</strong><pre>%s</pre></div>`,
				htmlEscape(r.POC))
		}

		remediationDisplay := ""
		if r.Remediation != "" {
			remediationDisplay = fmt.Sprintf(`<div class="remediation-box"><strong>🔧 Remediation:</strong> %s</div>`,
				htmlEscape(r.Remediation))
		}

		card := fmt.Sprintf(`
        <div class="vuln-card severity-%s">
            <div class="vuln-header">
                <div>
                    <div class="vuln-title">#%d %s</div>
                    <span class="severity-badge badge-%s">%s</span>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 1.5em; font-weight: bold; color: %s;">%.1f%%</div>
                    <div style="font-size: 0.85em; color: #64748b;">Confidence</div>
                </div>
            </div>
            <div class="vuln-details">
                <div class="detail-row">
                    <span class="detail-label">Target URL:</span>
                    <span>%s</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Malicious Origin:</span>
                    <span><code>%s</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Vulnerability:</span>
                    <span>%s</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Bypass Technique:</span>
                    <span>%s</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Description:</span>
                    <span>%s</span>
                </div>
                %s
                %s
            </div>
        </div>`,
			severityClass,
			i+1,
			htmlEscape(r.Title),
			badgeClass,
			r.Severity,
			getConfidenceColor(r.Confidence),
			r.Confidence,
			htmlEscape(r.URL),
			htmlEscape(r.Origin),
			htmlEscape(r.VulnType),
			htmlEscape(r.BypassTechnique),
			htmlEscape(r.Description),
			pocDisplay,
			remediationDisplay,
		)

		vulnCardsHTML.WriteString(card)
	}

	finalHTML := fmt.Sprintf(htmlTemplate,
		time.Now().Format(time.RFC1123),
		stats.TotalURLs,
		len(results),
		stats.TotalRequests,
		stats.TotalOriginsTested,
		vulnCardsHTML.String(),
	)

	err := os.WriteFile(filepath, []byte(finalHTML), 0644)
	if err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	color.Green("[✓] HTML report saved to: %s", filepath)
	return nil
}

// Helper types and functions
type Metadata struct {
	ScannerName string `json:"scanner_name"`
	Version     string `json:"version"`
	Timestamp   string `json:"timestamp"`
	Author      string `json:"author"`
}

func GetSeverityWithColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return color.RedString("%s", severity)
	case "HIGH":
		return color.RedString("%s", severity)
	case "MEDIUM":
		return color.YellowString("%s", severity)
	case "LOW":
		return color.GreenString("%s", severity)
	default:
		return color.CyanString("%s", severity)
	}
}

func countBySeverity(results []*core.ScanResult, severity string) int {
	count := 0
	for _, r := range results {
		if strings.ToUpper(r.Severity) == severity {
			count++
		}
	}
	return count
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func EscapeCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	if strings.ContainsAny(s, ",\"\n") {
		s = "\"" + s + "\""
	}
	return s
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func getSeverityClass(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "low"
	}
}

func getBadgeClass(severity string) string {
	return getSeverityClass(severity)
}

func getConfidenceColor(confidence float64) string {
	if confidence >= 90 {
		return "#dc2626"
	} else if confidence >= 70 {
		return "#d97706"
	} else {
		return "#16a34a"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
