package main

import (
	"os"
	"strings"
	"time"

	"github.com/youwannahackme/originstrike/config"
	"github.com/youwannahackme/originstrike/core"
	"github.com/youwannahackme/originstrike/report"
	"github.com/youwannahackme/originstrike/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	Version        = "2.0.0-GOD-MODE"
	Author         = "whoami_404"
	targetURLs     []string
	listFile       string
	outputFile     string
	outputFormat   string
	concurrency    int
	timeout        int
	verbose        bool
	silent         bool
	noColor        bool
	followRedirect bool
	userAgent      string
	customHeaders  map[string]string
	methods        []string
	originsFile    string
	delay          int
	retryCount     int
	cookie         string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "originstrike [flags]",
	Short: "🔥 Ultimate CORS Vulnerability Scanner - God Mode",
	Long: `
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

                         🔥 ULTIMATE CORS EXPLOITATION SUITE 🔥
                           Version 2.0.0 | Author: whoami_404
                            
OriginStrike v2.0 - The most advanced CORS vulnerability scanner & exploitation toolkit.
Designed for high-concurrency, deep-coverage security assessments with a Zero False Positive Guarantee.

CORE CAPABILITIES:
    • Advanced Multi-Origin Fuzzing (1000+ payload variations)
    • Null Byte Injection & Encoding Bypass Detection
    • Credential Leakage Verification (Credentials allowed check)
    • Preflight Request Analysis (OPTIONS method validation)
    • Labeled/Custom Headers & Regex Pattern Matching
    • Multi-Format Reporting (JSON, CSV, HTML)`,
	Example: `  # Scan a single target:
  originstrike -u https://example.com

  # Scan multiple targets concurrently with 20 workers and output an HTML report:
  originstrike -u target1.com,target2.com -c 20 -o report.html -f html

  # Scan a list of targets from a file with a 100ms delay:
  originstrike -l targets.txt -d 100 -o results.json`,
	Run: runScanner,
}

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&targetURLs, "url", "u", nil, "Target URL(s) to scan")
	rootCmd.PersistentFlags().StringVarP(&listFile, "list", "l", "", "File containing list of target URLs to scan")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json/csv/html)")
	rootCmd.PersistentFlags().IntVarP(&concurrency, "concurrency", "c", 50, "Concurrency level")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Silent mode")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&followRedirect, "follow-redirect", "r", false, "Follow redirects")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "OriginStrike/2.0", "Custom User-Agent")
	rootCmd.PersistentFlags().StringSliceVar(&methods, "methods", []string{"GET", "OPTIONS", "POST"}, "HTTP methods to test")
	rootCmd.PersistentFlags().StringVar(&originsFile, "origins-file", "", "File containing custom origins")
	rootCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Delay between requests (ms)")
	rootCmd.PersistentFlags().IntVar(&retryCount, "retries", 3, "Retry count on failure")
	rootCmd.PersistentFlags().StringVar(&cookie, "cookie", "", "Custom Cookie header value (e.g., 'session=1234')")
}

func runScanner(cmd *cobra.Command, args []string) {
	// Combine and parse target URLs from -u and -l flags
	var allTargets []string
	if len(targetURLs) > 0 {
		parsed, err := utils.ParseTargets(targetURLs)
		if err != nil {
			color.Red("Error parsing target URLs: %v", err)
			os.Exit(1)
		}
		allTargets = append(allTargets, parsed...)
	}
	if listFile != "" {
		if !utils.IsFile(listFile) {
			color.Red("Error: target list file '%s' specified with -l/--list does not exist or is not a valid file", listFile)
			os.Exit(1)
		}
		listTargets, err := utils.ParseFromFile(listFile)
		if err != nil {
			color.Red("Error reading target list file '%s': %v", listFile, err)
			os.Exit(1)
		}
		allTargets = append(allTargets, listTargets...)
	}
	allTargets = utils.Deduplicate(allTargets)

	// Initialize configuration
	cfg := &config.Config{
		TargetURLs:     allTargets,
		OutputFile:     outputFile,
		OutputFormat:   outputFormat,
		Concurrency:    concurrency,
		Timeout:        time.Duration(timeout) * time.Second,
		Verbose:        verbose,
		Silent:         silent,
		NoColor:        noColor,
		FollowRedirect: followRedirect,
		UserAgent:      userAgent,
		Methods:        methods,
		OriginsFile:    originsFile,
		Delay:          time.Duration(delay) * time.Millisecond,
		RetryCount:     retryCount,
		CustomHeaders:  customHeaders,
		Cookie:         cookie,
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		color.Red("Configuration Error: %v", err)
		os.Exit(1)
	}

	// Print banner
	printBanner()

	// Initialize scanner
	scanner := core.NewScanner(cfg)

	// Start scanning
	color.Cyan("\n[+] Initializing Advanced CORS Scanning Engine...")

	startTime := time.Now()
	results, err := scanner.Start()
	if err != nil {
		color.Red("Scanning Error: %v", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)

	// Generate report
	if len(results) > 0 {
		color.Green("\n[✓] Scan Completed! Found %d CORS Misconfiguration(s)", len(results))

		if outputFile != "" {
			generateReport(results, cfg, scanner.GetStats())
		}

		displayResults(results)
	} else {
		color.Yellow("\n[-] No CORS vulnerabilities detected")
	}

	// Print statistics
	printStatistics(scanner.GetStats(), duration)
}

func printBanner() {
	banner := `
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

            🔥 GOD MODE ACTIVATED - ZERO FALSE POSITIVES 🔥
`
	color.Cyan(banner)
	color.White("  Version: %s | Author: %s | Build: Extreme Power Edition\n\n", Version, Author)
}

func displayResults(results []*core.ScanResult) {
	color.Cyan("\n" + strings.Repeat("═", 80))
	color.Cyan("                    🎯 VULNERABILITY DETAILS")
	color.Cyan(strings.Repeat("═", 80))

	for i, result := range results {
		color.White("\n[%d] Target: %s", i+1, result.URL)
		color.Red("    Status: VULNERABLE")
		color.Yellow("    Severity: %s", result.Severity)
		color.Cyan("    Type: %s", result.VulnType)
		color.White("    Description: %s", result.Description)

		if result.POC != "" {
			color.Green("    Proof of Concept:\n%s", indentText(result.POC, 8))
		}

		if len(result.Headers) > 0 {
			color.Magenta("    Affected Headers:")
			for k, v := range result.Headers {
				color.White("      %s: %s", k, v)
			}
		}

		if result.Remediation != "" {
			color.Cyan("    Remediation: %s", result.Remediation)
		}
	}
}

func indentText(text string, spaces int) string {
	indent := strings.Repeat(" ", spaces)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

func generateReport(results []*core.ScanResult, cfg *config.Config, stats *core.ScanStats) {
	var reporter report.Reporter

	switch cfg.OutputFormat {
	case "json":
		reporter = report.NewJSONReporter(cfg.OutputFile)
	case "csv":
		reporter = report.NewCSVReporter(cfg.OutputFile)
	case "html":
		reporter = report.NewHTMLReporter(cfg.OutputFile)
	default:
		reporter = report.NewJSONReporter(cfg.OutputFile)
	}

	if err := reporter.Generate(results, stats); err != nil {
		color.Red("Failed to generate report: %v", err)
	} else {
		color.Green("Report saved to: %s", cfg.OutputFile)
	}
}

func printStatistics(stats *core.ScanStats, duration time.Duration) {
	color.Cyan("\n" + strings.Repeat("═", 80))
	color.Cyan("                    📊 SCAN STATISTICS")
	color.Cyan(strings.Repeat("═", 80))
	color.White("    ├─ Scan Duration:     %v", duration.Round(time.Millisecond))
	color.White("    ├─ Total URLs:        %d", stats.TotalURLs)
	color.White("    ├─ Scanned URLs:      %d", stats.ScannedURLs)
	color.White("    ├─ Vulnerable URLs:   %d", stats.VulnerableURLs)
	color.White("    ├─ Requests Sent:     %d", stats.TotalRequests)
	color.White("    └─ Origins Tested:    %d", stats.TotalOriginsTested)
	color.Cyan(strings.Repeat("═", 80))
}
