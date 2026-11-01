package main

import (
	"fmt"
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
	showAll        bool
	showFailed     bool
	proxyURL       string
	insecure       bool
	jsonFlag       bool
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
	rootCmd.PersistentFlags().StringVarP(&proxyURL, "proxy", "x", "", "HTTP/HTTPS/SOCKS5 proxy URL (e.g., http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "Output format as JSON")
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification")
	rootCmd.PersistentFlags().BoolVarP(&showAll, "show-all", "a", false, "Show all results on CLI including safe checks and failed verifications")
	rootCmd.PersistentFlags().BoolVar(&showFailed, "show-failed", false, "Show failed verifications and filtered results on CLI")

	rootCmd.SetHelpFunc(customHelpFunc)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
}

func runScanner(cmd *cobra.Command, args []string) {
	if noColor {
		color.NoColor = true
	}

	if jsonFlag {
		outputFormat = "json"
	}

	if len(targetURLs) == 0 && listFile == "" && len(args) > 0 {
		targetURLs = args
	}

	if len(targetURLs) == 0 && listFile == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			listFile = "-"
		} else {
			cmd.Help()
			return
		}
	}

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
		ShowAll:        showAll,
		ShowFailed:     showFailed,
		ProxyURL:       proxyURL,
		Insecure:       insecure,
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
	color.New(color.FgHiBlue, color.Bold).Printf("[INFO] ")
	color.New(color.FgWhite).Printf("Processing %d URL(s) with %d origin payloads across 6 detection phases.\n\n", len(allTargets), scanner.GetTotalPayloadCount())

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
	} else {
		color.Yellow("\n[-] No confirmed CORS vulnerabilities detected")
	}

	displayResults(results, scanner.GetFailedResults(), scanner.GetSafeResults(), cfg)

	// Print statistics
	printStatistics(scanner.GetStats(), duration)
}

type flagInfo struct {
	name string
	desc string
}

func printFlagGroup(title string, flags []flagInfo) {
	color.New(color.FgHiYellow, color.Bold).Printf("  ▪ %s:\n", title)
	for _, f := range flags {
		flagCol := color.New(color.FgHiGreen, color.Bold).Sprintf("    %-30s", f.name)
		descCol := color.New(color.FgWhite).Sprintf("%s", f.desc)
		fmt.Printf("%s %s\n", flagCol, descCol)
	}
	fmt.Println()
}

func customHelpFunc(cmd *cobra.Command, args []string) {
	printBanner()

	color.New(color.FgHiCyan, color.Bold).Println("📖 DESCRIPTION:")
	color.New(color.FgWhite).Println("  OriginStrike v2.0 - The most advanced CORS vulnerability scanner & exploitation toolkit.")
	color.New(color.FgWhite).Printf("  Designed for high-concurrency, deep-coverage security assessments with a Zero False Positive Guarantee.\n\n")

	color.New(color.FgHiCyan, color.Bold).Println("🛡️  CORE CAPABILITIES:")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Println("Advanced Multi-Origin Fuzzing (1000+ payload variations across 6 detection phases)")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Println("Null Byte Injection & Encoding Bypass Detection")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Println("Credential Leakage Verification (Access-Control-Allow-Credentials validation)")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Println("Preflight Request Analysis (OPTIONS method verification)")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Println("Partial/Regex Match & Labeled Header Reflection Analysis")
	color.New(color.FgHiGreen, color.Bold).Print("  ✔  ")
	color.New(color.FgWhite).Printf("Multi-Format Structured Reporting (JSON, CSV, HTML)\n\n")

	color.New(color.FgHiCyan, color.Bold).Println("🚀 USAGE:")
	color.New(color.FgHiYellow, color.Bold).Printf("  originstrike [flags]\n\n")

	color.New(color.FgHiCyan, color.Bold).Println("💡 EXAMPLES:")
	color.New(color.FgHiBlack, color.Bold).Println("  # Scan a single target URL:")
	color.New(color.FgHiGreen).Printf("  originstrike -u https://example.com\n\n")
	color.New(color.FgHiBlack, color.Bold).Println("  # Scan multiple targets with 50 workers and generate an HTML report:")
	color.New(color.FgHiGreen).Printf("  originstrike -u target1.com,target2.com -c 50 -o report.html -f html\n\n")
	color.New(color.FgHiBlack, color.Bold).Println("  # Scan a list of targets from file, show all findings, with a 100ms delay:")
	color.New(color.FgHiGreen).Printf("  originstrike -l targets.txt -d 100 -a -o results.json\n\n")

	color.New(color.FgHiCyan, color.Bold).Println("🚩 FLAGS & OPTIONS:")

	printFlagGroup("TARGET SPECIFICATION", []flagInfo{
		{"-u, --url <strings>", "Target URL(s) to scan (comma-separated or multiple -u flags)"},
		{"-l, --list <file>", "File containing list of target URLs to scan"},
		{"--origins-file <file>", "File containing custom origin payloads to append"},
	})

	printFlagGroup("SCAN CONFIGURATION & PERFORMANCE", []flagInfo{
		{"-c, --concurrency <int>", "Number of concurrent worker goroutines (default: 50)"},
		{"-t, --timeout <int>", "HTTP request timeout in seconds (default: 10)"},
		{"-d, --delay <int>", "Delay between requests in milliseconds (default: 0)"},
		{"--retries <int>", "Number of retries on failed/timed-out requests (default: 3)"},
		{"--methods <strings>", "HTTP methods to test (default: [GET,OPTIONS,POST])"},
		{"-r, --follow-redirect", "Follow HTTP redirects during scanning (default: false)"},
	})

	printFlagGroup("AUTHENTICATION & NETWORK", []flagInfo{
		{"--cookie <string>", "Custom Cookie header value (e.g., 'session=1234; auth=token')"},
		{"--user-agent <string>", "Custom User-Agent header (default: OriginStrike/2.0)"},
		{"--proxy <url>", "HTTP/HTTPS/SOCKS5 proxy URL (e.g., http://127.0.0.1:8080)"},
		{"-k, --insecure", "Skip TLS certificate verification (allow self-signed certs)"},
	})

	printFlagGroup("REPORTING & OUTPUT", []flagInfo{
		{"-o, --output <file>", "Output file path to save report"},
		{"-f, --format <string>", "Output report format: json | csv | html (default: json)"},
		{"-a, --show-all", "Show all results on CLI including safe origin checks and non-vulnerable info"},
		{"--show-failed", "Show failed verifications and filtered results on CLI"},
		{"-v, --verbose", "Enable detailed verbose real-time logging"},
		{"-s, --silent", "Silent mode (suppress real-time terminal output, only print summary/report)"},
		{"--no-color", "Disable colored terminal output"},
		{"-h, --help", "Display this help menu and exit"},
	})
}

func printBanner() {
	banner := `
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝`

	bannerColor := color.New(color.FgHiCyan, color.Bold)
	bannerColor.Println(banner)
	bannerColor.Printf("  ⚡ [v%s] | God-Mode CORS Exploitation Suite | Author: %s\n", Version, Author)
	bannerColor.Printf("  %s\n\n", strings.Repeat("━", 78))
}

func displayResults(results []*core.ScanResult, failedResults []*core.ScanResult, safeResults []*core.ScanResult, cfg *config.Config) {
	if len(results) > 0 {
		color.Cyan("\n" + strings.Repeat("═", 80))
		color.Cyan("                    🎯 CONFIRMED VULNERABILITY DETAILS")
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

	if (cfg.ShowAll || cfg.ShowFailed || cfg.Verbose) && len(failedResults) > 0 {
		color.Yellow("\n" + strings.Repeat("═", 80))
		color.Yellow("              ⚠️ FAILED VERIFICATION & FILTERED CANDIDATES")
		color.Yellow(strings.Repeat("═", 80))

		for i, result := range failedResults {
			color.White("\n[%d] Target: %s", i+1, result.URL)
			color.Yellow("    Status: %s", result.Status)
			color.Cyan("    Type: %s (Origin: %s)", result.VulnType, result.Origin)
			color.White("    Reason/Description: %s", result.Description)
		}
	}

	if cfg.ShowAll && len(safeResults) > 0 {
		color.Green("\n" + strings.Repeat("═", 80))
		color.Green("                  🛡️ SAFE / NON-VULNERABLE CHECKS")
		color.Green(strings.Repeat("═", 80))

		maxDisplay := len(safeResults)
		if maxDisplay > 100 && !cfg.Verbose {
			color.White("\nShowing first 100 safe checks out of %d total (use -v for all):", len(safeResults))
			maxDisplay = 100
		}
		for i := 0; i < maxDisplay; i++ {
			result := safeResults[i]
			color.White("\n[%d] Target: %s", i+1, result.URL)
			color.Green("    Status: SAFE")
			color.Cyan("    Check: %s (Origin: %s)", result.VulnType, result.Origin)
			color.White("    Description: %s", result.Description)
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
