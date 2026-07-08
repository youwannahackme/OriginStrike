package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/youwannahackme/originstrike/core"
)

type CSVReporter struct {
	*BaseReporter
	delimiter      rune
	includeHeaders bool
	customColumns  []string
}

func NewCSVReporter(outputPath string) *CSVReporter {
	return &CSVReporter{
		BaseReporter:   NewBaseReporter(outputPath),
		delimiter:      ',',
		includeHeaders: true,
		customColumns:  []string{},
	}
}

func (cr *CSVReporter) SetDelimiter(delimiter rune) {
	cr.delimiter = delimiter
}

func (cr *CSVReporter) SetCustomColumns(columns []string) {
	cr.customColumns = columns
}

func (cr *CSVReporter) SupportedFormats() []string {
	return []string{"csv"}
}

func (cr *CSVReporter) Validate() error {
	if cr.outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	validExts := map[string]bool{".csv": true, ".tsv": true}
	ext := strings.ToLower(cr.outputPath[strings.LastIndex(cr.outputPath, "."):])
	if !validExts[ext] {
		return fmt.Errorf("output file must have .csv or .tsv extension")
	}
	return nil
}

func (cr *CSVReporter) Generate(results []*core.ScanResult, stats *core.ScanStats) error {
	if err := cr.Validate(); err != nil {
		return err
	}

	file, err := os.Create(cr.outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Comma = cr.delimiter

	// Write header
	if cr.includeHeaders {
		headers := cr.getHeaders()
		if err := writer.Write(headers); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
	}

	// Write data rows
	for _, result := range results {
		row := cr.convertToRow(result)
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		return fmt.Errorf("error flushing CSV writer: %w", err)
	}

	return nil
}

func (cr *CSVReporter) getHeaders() []string {
	baseHeaders := []string{
		"ID",
		"URL",
		"Origin",
		"Method",
		"HTTP_Status_Code",
		"Severity",
		"Vulnerability_Type",
		"Title",
		"Description",
		"Confidence_Score",
		"Is_Confirmed",
		"Bypass_Technique",
		"Timestamp",
		"Remediation",
	}

	if cr.includePOC {
		baseHeaders = append(baseHeaders, "Proof_of_Concept")
	}

	// Add custom columns
	baseHeaders = append(baseHeaders, cr.customColumns...)

	return baseHeaders
}

func (cr *CSVReporter) convertToRow(result *core.ScanResult) []string {
	row := []string{
		result.ID,
		result.URL,
		result.Origin,
		result.Method,
		strconv.Itoa(result.StatusCode),
		result.Severity,
		result.VulnType,
		result.Title,
		result.Description,
		strconv.FormatFloat(result.Confidence, 'f', 2, 64),
		strconv.FormatBool(result.IsConfirmed),
		result.BypassTechnique,
		result.Timestamp.Format(time.RFC3339),
		result.Remediation,
	}

	if cr.includePOC {
		// Clean up POC for CSV (remove newlines)
		pocClean := strings.ReplaceAll(result.POC, "\n", "\\n")
		pocClean = strings.ReplaceAll(pocClean, "\r", "")
		pocClean = strings.ReplaceAll(pocClean, ",", ",")
		row = append(row, pocClean)
	}

	return row
}

// Additional CSV utility methods
func (cr *CSVReporter) GenerateSummaryOnly(stats *core.ScanStats) error {
	file, err := os.Create(cr.outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Comma = cr.delimiter

	headers := []string{"Metric", "Value"}
	writer.Write(headers)

	data := [][]string{
		{"Total URLs Scanned", strconv.FormatInt(stats.TotalURLs, 10)},
		{"Vulnerable URLs", strconv.FormatInt(stats.VulnerableURLs, 10)},
		{"Total Requests Sent", strconv.FormatInt(stats.TotalRequests, 10)},
		{"Total Origins Tested", strconv.FormatInt(stats.TotalOriginsTested, 10)},
		{"Start Time", stats.StartTime.Format(time.RFC3339)},
		{"End Time", stats.EndTime.Format(time.RFC3339)},
		{"Duration", stats.EndTime.Sub(stats.StartTime).String()},
	}

	for _, row := range data {
		writer.Write(row)
	}

	writer.Flush()
	return writer.Error()
}
