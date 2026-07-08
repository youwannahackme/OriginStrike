package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/youwannahackme/originstrike/core"
)

type HTMLReporter struct {
	*BaseReporter
	template      *template.Template
	customCSS     string
	customJS      string
	theme         string
	interactive   bool
	includeCharts bool
}

func NewHTMLReporter(outputPath string) *HTMLReporter {
	return &HTMLReporter{
		BaseReporter:  NewBaseReporter(outputPath),
		theme:         "modern",
		interactive:   true,
		includeCharts: true,
	}
}

func (hr *HTMLReporter) SetTheme(theme string) {
	hr.theme = theme
}

func (hr *HTMLReporter) SetCustomCSS(css string) {
	hr.customCSS = css
}

func (hr *HTMLReporter) SetInteractive(interactive bool) {
	hr.interactive = interactive
}

func (hr *HTMLReporter) SetIncludeCharts(include bool) {
	hr.includeCharts = include
}

func (hr *HTMLReporter) SupportedFormats() []string {
	return []string{"html"}
}

func (hr *HTMLReporter) Validate() error {
	if hr.outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	if !strings.HasSuffix(strings.ToLower(hr.outputPath), ".html") {
		return fmt.Errorf("output file must have .html extension")
	}
	return nil
}

func (hr *HTMLReporter) Generate(results []*core.ScanResult, stats *core.ScanStats) error {
	if err := hr.Validate(); err != nil {
		return err
	}

	// Build template data
	data := hr.buildTemplateData(results, stats)

	// Parse and execute template
	tmpl, err := hr.getTemplate()
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	file, err := os.Create(hr.outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, data)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

func (hr *HTMLReporter) buildTemplateData(results []*core.ScanResult, stats *core.ScanStats) TemplateData {
	summary := CalculateSummaryStats(results, stats)

	data := TemplateData{
		Metadata: Metadata{
			ScannerName: "OriginStrike",
			Version:     "2.0-GOD-MODE",
			GeneratedAt: hr.generatedAt.Format(time.RFC3339Nano),
			Author:      "whoami_404",
			Description: "Advanced CORS Vulnerability Security Assessment",
		},
		Summary:         summary,
		Statistics:      stats,
		Vulnerabilities: results,
		Theme:           hr.theme,
		Interactive:     hr.interactive,
		IncludeCharts:   hr.includeCharts,
		CustomCSS:       hr.customCSS,
		GeneratedAt:     hr.generatedAt,
	}

	return data
}

func (hr *HTMLReporter) getTemplate() (*template.Template, error) {
	tmplStr := hr.getHTMLTemplate()

	funcMap := template.FuncMap{
		"upper":         strings.ToUpper,
		"lower":         strings.ToLower,
		"title":         strings.Title,
		"join":          strings.Join,
		"seq":           generateSequence,
		"safeHTML":      safeHTML,
		"severityColor": getSeverityColor,
		"severityIcon":  getSeverityIcon,
		"formatDate":    formatDate,
		"truncate":      truncateString,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

func (hr *HTMLReporter) getHTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{.Metadata.ScannerName}} Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
        }
        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(30, 58, 138, 0.25) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(88, 28, 135, 0.15) 0px, transparent 50%);
            color: var(--text-primary);
            font-family: 'Outfit', sans-serif;
            margin: 0;
            padding: 2rem;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        .header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 50%, #8b5cf6 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.5rem;
            margin-bottom: 3rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
            border-radius: 1rem;
            text-align: center;
            backdrop-filter: blur(10px);
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 0.25rem;
        }
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .severity-breakdown {
            display: flex;
            gap: 1rem;
            margin-bottom: 3rem;
            justify-content: center;
        }
        .severity-badge {
            padding: 0.5rem 1.25rem;
            border-radius: 0.5rem;
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .critical { background: rgba(220, 38, 38, 0.15); color: #ef4444; border: 1px solid rgba(220, 38, 38, 0.3); }
        .high { background: rgba(234, 88, 12, 0.15); color: #f97316; border: 1px solid rgba(234, 88, 12, 0.3); }
        .medium { background: rgba(217, 119, 6, 0.15); color: #f59e0b; border: 1px solid rgba(217, 119, 6, 0.3); }
        .low { background: rgba(22, 163, 74, 0.15); color: #10b981; border: 1px solid rgba(22, 163, 74, 0.3); }
        .vuln-list {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }
        .vuln-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 1.25rem;
            padding: 2rem;
            backdrop-filter: blur(10px);
            transition: transform 0.3s, border-color 0.3s;
        }
        .vuln-card:hover {
            transform: translateY(-2px);
            border-color: rgba(59, 130, 246, 0.3);
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
        }
        .vuln-title {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .vuln-target {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-cyan);
            font-size: 0.9rem;
        }
        .badge {
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            padding: 0.25rem 0.6rem;
            border-radius: 0.375rem;
        }
        .vuln-body {
            margin-top: 1rem;
        }
        .vuln-desc {
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        .section-title {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--accent-blue);
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        .header-list {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            margin-bottom: 1.5rem;
        }
        .poc-block {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 1rem;
            overflow-x: auto;
            margin-bottom: 1.5rem;
        }
        .poc-block pre {
            margin: 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #d1d5db;
        }
        .remediation {
            background: rgba(6, 182, 212, 0.05);
            border-left: 3px solid var(--accent-cyan);
            padding: 0.75rem 1rem;
            border-radius: 0 0.5rem 0.5rem 0;
            font-size: 0.95rem;
        }
        {{if .CustomCSS}}{{.CustomCSS}}{{end}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CORS Security Report</h1>
            <p>Generated by {{.Metadata.ScannerName}} v{{.Metadata.Version}} at {{.Metadata.GeneratedAt}}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{.Summary.TotalURLs}}</div>
                <div class="stat-label">Total Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Summary.VulnerableURLs}}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Summary.TotalRequests}}</div>
                <div class="stat-label">Requests Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{printf "%.1f%%" .Summary.AvgConfidence}}</div>
                <div class="stat-label">Avg Confidence</div>
            </div>
        </div>

        <div class="severity-breakdown">
            <div class="severity-badge critical">☠️ Critical: {{index .Summary.BySeverity "CRITICAL"}}</div>
            <div class="severity-badge high">🔴 High: {{index .Summary.BySeverity "HIGH"}}</div>
            <div class="severity-badge medium">🟡 Medium: {{index .Summary.BySeverity "MEDIUM"}}</div>
            <div class="severity-badge low">🟢 Low: {{index .Summary.BySeverity "LOW"}}</div>
        </div>

        <div class="vuln-list">
            {{range $idx, $vuln := .Vulnerabilities}}
            <div class="vuln-card">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-title">{{$vuln.Title}}</div>
                        <div class="vuln-target">{{$vuln.Method}} {{$vuln.URL}}</div>
                    </div>
                    <span class="badge {{lower $vuln.Severity}}">{{$vuln.Severity}}</span>
                </div>
                <div class="vuln-body">
                    <div class="vuln-desc">{{$vuln.Description}}</div>
                    
                    {{if $vuln.Headers}}
                    <div class="section-title">Affected Headers</div>
                    <div class="header-list">
                        {{range $name, $val := $vuln.Headers}}
                        <div><strong>{{$name}}</strong>: {{$val}}</div>
                        {{end}}
                    </div>
                    {{end}}

                    {{if $vuln.POC}}
                    <div class="section-title">Proof of Concept</div>
                    <div class="poc-block">
                        <pre>{{$vuln.POC}}</pre>
                    </div>
                    {{end}}

                    {{if $vuln.Remediation}}
                    <div class="section-title">Remediation</div>
                    <div class="remediation">
                        {{$vuln.Remediation}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{else}}
            <div style="text-align: center; color: var(--text-secondary); padding: 3rem;">
                No vulnerabilities detected.
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`
}

// Template data structures
type TemplateData struct {
	Metadata        Metadata
	Summary         SummaryStatistics
	Statistics      *core.ScanStats
	Vulnerabilities []*core.ScanResult
	Theme           string
	Interactive     bool
	IncludeCharts   bool
	CustomCSS       string
	GeneratedAt     time.Time
}

// Template helper functions
func generateSequence(start, end int) []int {
	var seq []int
	for i := start; i <= end; i++ {
		seq = append(seq, i)
	}
	return seq
}

func safeHTML(s string) template.HTML {
	return template.HTML(s)
}

func getSeverityColor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "#dc2626"
	case "HIGH":
		return "#ea580c"
	case "MEDIUM":
		return "#d97706"
	case "LOW":
		return "#16a34a"
	default:
		return "#6b7280"
	}
}

func getSeverityIcon(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "☠️"
	case "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "ℹ️"
	}
}

func formatDate(t time.Time) string {
	return t.Format("Jan 02, 2006 15:04 MST")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
