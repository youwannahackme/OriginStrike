package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/youwannahackme/originstrike/core"
)

type JSONReporter struct {
	*BaseReporter
	prettyPrint    bool
	includeStats   bool
	includeSummary bool
}

func NewJSONReporter(outputPath string) *JSONReporter {
	return &JSONReporter{
		BaseReporter:   NewBaseReporter(outputPath),
		prettyPrint:    true,
		includeStats:   true,
		includeSummary: true,
	}
}

func (jr *JSONReporter) SetPrettyPrint(pretty bool) {
	jr.prettyPrint = pretty
}

func (jr *JSONReporter) SupportedFormats() []string {
	return []string{"json"}
}

func (jr *JSONReporter) Validate() error {
	if jr.outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	if !strings.HasSuffix(jr.outputPath, ".json") {
		return fmt.Errorf("output file must have .json extension")
	}
	return nil
}

func (jr *JSONReporter) Generate(results []*core.ScanResult, stats *core.ScanStats) error {
	if err := jr.Validate(); err != nil {
		return err
	}

	report := jr.buildReport(results, stats)

	var jsonData []byte
	var err error

	if jr.prettyPrint {
		jsonData, err = json.MarshalIndent(report, "", "  ")
	} else {
		jsonData, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	err = os.WriteFile(jr.outputPath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

func (jr *JSONReporter) buildReport(results []*core.ScanResult, stats *core.ScanStats) JSONReport {
	summary := CalculateSummaryStats(results, stats)

	report := JSONReport{
		SchemaVersion: "2.0",
		Metadata: Metadata{
			ScannerName: "OriginStrike",
			Version:     "2.0-GOD-MODE",
			GeneratedAt: jr.generatedAt.Format(time.RFC3339),
			Author:      "whoami_404",
			Description: "Advanced CORS Vulnerability Assessment Report",
		},
		GeneratedAt: jr.generatedAt,
	}

	if jr.includeSummary {
		report.Summary = summary
	}

	if jr.includeStats {
		report.Statistics = stats
	}

	// Process vulnerabilities
	for _, result := range results {
		vuln := jr.convertToVulnerability(result)
		report.Vulnerabilities = append(report.Vulnerabilities, vuln)
	}

	// Update metadata counts
	report.Metadata.TotalVulns = len(results)
	report.Metadata.CriticalCount = summary.BySeverity["CRITICAL"]
	report.Metadata.HighCount = summary.BySeverity["HIGH"]
	report.Metadata.MediumCount = summary.BySeverity["MEDIUM"]
	report.Metadata.LowCount = summary.BySeverity["LOW"]
	report.Metadata.Duration = stats.EndTime.Sub(stats.StartTime).String()
	report.Metadata.TargetCount = int(stats.TotalURLs)

	// Add custom fields
	if len(jr.customFields) > 0 {
		report.CustomFields = jr.customFields
	}

	return report
}

func (jr *JSONReporter) convertToVulnerability(result *core.ScanResult) Vulnerability {
	vuln := Vulnerability{
		ID:              result.ID,
		URL:             result.URL,
		Origin:          result.Origin,
		Method:          result.Method,
		Status:          result.Status,
		StatusCode:      result.StatusCode,
		Severity:        result.Severity,
		VulnType:        result.VulnType,
		Title:           result.Title,
		Description:     result.Description,
		Confidence:      result.Confidence,
		IsConfirmed:     result.IsConfirmed,
		BypassTechnique: result.BypassTechnique,
		Timestamp:       result.Timestamp.Format(time.RFC3339),
		Remediation:     result.Remediation,
	}

	if jr.includePOC {
		vuln.ProofOfConcept = result.POC
	}

	if jr.includeRemediation {
		vuln.Remediation = result.Remediation
	}

	if len(result.Headers) > 0 {
		vuln.AffectedHeaders = result.Headers
	}

	return vuln
}

// JSON data structures
type JSONReport struct {
	SchemaVersion   string            `json:"schema_version"`
	Metadata        Metadata          `json:"metadata"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Summary         SummaryStatistics `json:"summary,omitempty"`
	Statistics      *core.ScanStats   `json:"statistics,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	CustomFields    map[string]string `json:"custom_fields,omitempty"`
}

type Vulnerability struct {
	ID              string            `json:"id"`
	URL             string            `json:"url"`
	Origin          string            `json:"origin"`
	Method          string            `json:"method"`
	Status          string            `json:"status"`
	StatusCode      int               `json:"status_code"`
	Severity        string            `json:"severity"`
	VulnType        string            `json:"vulnerability_type"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	ProofOfConcept  string            `json:"proof_of_concept,omitempty"`
	AffectedHeaders map[string]string `json:"affected_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	Confidence      float64           `json:"confidence_score"`
	IsConfirmed     bool              `json:"is_confirmed"`
	BypassTechnique string            `json:"bypass_technique"`
	Timestamp       string            `json:"discovered_at"`
	Remediation     string            `json:"remediation,omitempty"`
	References      []string          `json:"references,omitempty"`
	CVSSScore       float64           `json:"cvss_score,omitempty"`
	CWEID           string            `json:"cwe_id,omitempty"`
}

func (v *Vulnerability) AddReference(ref string) {
	v.References = append(v.References, ref)
}

func (v *Vulnerability) SetCVSS(score float64) {
	v.CVSSScore = score
}

func (v *Vulnerability) SetCWE(cwe string) {
	v.CWEID = cwe
}
