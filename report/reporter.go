package report

import (
	"github.com/youwannahackme/originstrike/core"
	"fmt"
	"time"
)

// Reporter interface defines the contract for all reporters
type Reporter interface {
	Generate(results []*core.ScanResult, stats *core.ScanStats) error
	SetOutputPath(path string)
	GetOutputPath() string
	SupportedFormats() []string
	Validate() error
}

// BaseReporter provides common functionality for all reporters
type BaseReporter struct {
	outputPath         string
	templateDir        string
	includePOC         bool
	includeRemediation bool
	customFields       map[string]string
	generatedAt        time.Time
}

func NewBaseReporter(outputPath string) *BaseReporter {
	return &BaseReporter{
		outputPath:         outputPath,
		includePOC:         true,
		includeRemediation: true,
		customFields:       make(map[string]string),
		generatedAt:        time.Now(),
	}
}

func (br *BaseReporter) SetOutputPath(path string) {
	br.outputPath = path
}

func (br *BaseReporter) GetOutputPath() string {
	return br.outputPath
}

func (br *BaseReporter) IncludePOC(include bool) {
	br.includePOC = include
}

func (br *BaseReporter) IncludeRemediation(include bool) {
	br.includeRemediation = include
}

func (br *BaseReporter) AddCustomField(key, value string) {
	br.customFields[key] = value
}

// Metadata contains common metadata for reports
type Metadata struct {
	ScannerName   string    `json:"scanner_name"`
	Version       string    `json:"version"`
	GeneratedAt   string    `json:"generated_at"`
	Author        string    `json:"author"`
	Description   string    `json:"description,omitempty"`
	TotalVulns    int       `json:"total_vulnerabilities"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	LowCount      int       `json:"low_count"`
	Duration      string    `json:"duration"`
	TargetCount   int       `json:"target_count"`
}

// GenerateReport creates the appropriate reporter based on format
func GenerateReport(format string, outputPath string) (Reporter, error) {
	switch format {
	case "json", "":
		return NewJSONReporter(outputPath), nil
	case "csv":
		return NewCSVReporter(outputPath), nil
	case "html":
		return NewHTMLReporter(outputPath), nil
	case "sarif":
		return nil, fmt.Errorf("SARIF report format is not implemented yet")
	case "pdf":
		return nil, fmt.Errorf("PDF report format is not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// SummaryStatistics provides aggregated statistics
type SummaryStatistics struct {
	TotalURLs          int            `json:"total_urls_scanned"`
	VulnerableURLs     int            `json:"vulnerable_urls"`
	TotalRequests      int64          `json:"total_requests_sent"`
	TotalOriginsTested int64          `json:"total_origins_tested"`
	ScanDuration       string         `json:"scan_duration"`
	StartTime          time.Time      `json:"start_time"`
	EndTime            time.Time      `json:"end_time"`
	BySeverity         map[string]int `json:"by_severity"`
	ByType             map[string]int `json:"by_vulnerability_type"`
	ByBypassTechnique  map[string]int `json:"by_bypass_technique"`
	AvgConfidence      float64        `json:"average_confidence"`
	MinConfidence      float64        `json:"min_confidence"`
	MaxConfidence      float64        `json:"max_confidence"`
}

func CalculateSummaryStats(results []*core.ScanResult, stats *core.ScanStats) SummaryStatistics {
	totalURLs := 0
	totalRequests := int64(0)
	totalOriginsTested := int64(0)
	scanDuration := "0s"
	var startTime, endTime time.Time

	if stats != nil {
		totalURLs = int(stats.TotalURLs)
		totalRequests = stats.TotalRequests
		totalOriginsTested = stats.TotalOriginsTested
		if !stats.StartTime.IsZero() && !stats.EndTime.IsZero() {
			scanDuration = stats.EndTime.Sub(stats.StartTime).String()
		}
		startTime = stats.StartTime
		endTime = stats.EndTime
	}

	summary := SummaryStatistics{
		TotalURLs:          totalURLs,
		VulnerableURLs:     len(uniqueURLs(results)),
		TotalRequests:      totalRequests,
		TotalOriginsTested: totalOriginsTested,
		ScanDuration:       scanDuration,
		StartTime:          startTime,
		EndTime:            endTime,
		BySeverity:         make(map[string]int),
		ByType:             make(map[string]int),
		ByBypassTechnique:  make(map[string]int),
	}

	var totalConfidence float64
	minConf := 100.0
	maxConf := 0.0

	for _, r := range results {
		summary.BySeverity[r.Severity]++
		summary.ByType[r.VulnType]++

		if r.BypassTechnique != "" {
			summary.ByBypassTechnique[r.BypassTechnique]++
		}

		totalConfidence += r.Confidence

		if r.Confidence < minConf {
			minConf = r.Confidence
		}
		if r.Confidence > maxConf {
			maxConf = r.Confidence
		}
	}

	if len(results) > 0 {
		summary.AvgConfidence = totalConfidence / float64(len(results))
		summary.MinConfidence = minConf
		summary.MaxConfidence = maxConf
	}

	return summary
}

func uniqueURLs(results []*core.ScanResult) []string {
	seen := make(map[string]bool)
	var urls []string

	for _, r := range results {
		if !seen[r.URL] {
			seen[r.URL] = true
			urls = append(urls, r.URL)
		}
	}

	return urls
}
