package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/youwannahackme/originstrike/core"
)

type HistoryManager struct {
	dir        string
	maxEntries int
	entries    []HistoryEntry
	mutex      sync.RWMutex
	index      map[string]int // URL -> index in entries slice
}

type HistoryEntry struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	TargetURL     string                 `json:"target_url"`
	TargetCount   int                    `json:"target_count"`
	Duration      time.Duration          `json:"duration"`
	Results       []*core.ScanResult     `json:"results"`
	Statistics    *core.ScanStats        `json:"statistics"`
	Summary       SummaryStatistics      `json:"summary"`
	Configuration map[string]interface{} `json:"configuration"`
	Tags          []string               `json:"tags"`
	Notes         string                 `json:"notes"`
}

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

type HistoryQuery struct {
	URLPattern  string    `json:"url_pattern,omitempty"`
	StartDate   time.Time `json:"start_date,omitempty"`
	EndDate     time.Time `json:"end_date,omitempty"`
	MinSeverity string    `json:"min_severity,omitempty"`
	HasVulns    *bool     `json:"has_vulnerabilities,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
	SortBy      string    `json:"sort_by,omitempty"`    // "date", "severity", "duration"
	SortOrder   string    `json:"sort_order,omitempty"` // "asc", "desc"
}

type HistoryStats struct {
	TotalScans        int            `json:"total_scans"`
	TotalVulnsFound   int            `json:"total_vulnerabilities_found"`
	AverageDuration   time.Duration  `json:"average_duration"`
	LastScanTime      time.Time      `json:"last_scan_time"`
	MostVulnerableURL string         `json:"most_vulnerable_url"`
	TopVulnTypes      map[string]int `json:"top_vulnerability_types"`
}

func NewHistoryManager(historyDir string, maxEntries int) (*HistoryManager, error) {
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	hm := &HistoryManager{
		dir:        historyDir,
		maxEntries: maxEntries,
		entries:    make([]HistoryEntry, 0),
		index:      make(map[string]int),
	}

	// Load existing history
	if err := hm.loadHistory(); err != nil {
		fmt.Printf("Warning: Could not load scan history: %v\n", err)
	}

	return hm, nil
}

func (hm *HistoryManager) AddEntry(entry HistoryEntry) error {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	// Generate ID if not set
	if entry.ID == "" {
		entry.ID = generateEntryID()
	}

	// Add to entries
	hm.entries = append(hm.entries, entry)

	// Update index
	hm.index[entry.TargetURL] = len(hm.entries) - 1

	// Enforce max entries limit
	if len(hm.entries) > hm.maxEntries {
		hm.evictOldest()
	}

	// Persist to disk
	return hm.persistEntry(entry)
}

func (hm *HistoryManager) Query(query HistoryQuery) ([]HistoryEntry, error) {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	var results []HistoryEntry

	for _, entry := range hm.entries {
		// Apply filters
		if !hm.matchesQuery(entry, query) {
			continue
		}

		results = append(results, entry)
	}

	// Apply sorting
	results = hm.sortResults(results, query.SortBy, query.SortOrder)

	// Apply pagination
	if query.Offset > 0 {
		if query.Offset >= len(results) {
			return []HistoryEntry{}, nil
		}
		results = results[query.Offset:]
	}

	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results, nil
}

func (hm *HistoryManager) matchesQuery(entry HistoryEntry, query HistoryQuery) bool {
	// URL pattern filter
	if query.URLPattern != "" {
		if !containsMatch(entry.TargetURL, query.URLPattern) {
			return false
		}
	}

	// Date range filter
	if !query.StartDate.IsZero() && entry.Timestamp.Before(query.StartDate) {
		return false
	}
	if !query.EndDate.IsZero() && entry.Timestamp.After(query.EndDate) {
		return false
	}

	// Severity filter
	if query.MinSeverity != "" {
		if !hasMinimumSeverity(entry.Results, query.MinSeverity) {
			return false
		}
	}

	// Has vulnerabilities filter
	if query.HasVulns != nil {
		hasVulns := len(entry.Results) > 0
		if *query.HasVulns != hasVulns {
			return false
		}
	}

	// Tags filter
	if len(query.Tags) > 0 {
		if !hasAllTags(entry.Tags, query.Tags) {
			return false
		}
	}

	return true
}

func (hm *HistoryManager) sortResults(entries []HistoryEntry, sortBy, sortOrder string) []HistoryEntry {
	if sortBy == "" {
		sortBy = "date"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	sort.Slice(entries, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "date":
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		case "severity":
			less = getMaxSeverityRank(entries[i].Results) > getMaxSeverityRank(entries[j].Results)
		case "duration":
			less = entries[i].Duration < entries[j].Duration
		case "vuln_count":
			less = len(entries[i].Results) > len(entries[j].Results)
		default:
			less = entries[i].Timestamp.Before(entries[j].Timestamp)
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	return entries
}

func (hm *HistoryManager) GetEntry(id string) (*HistoryEntry, error) {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	for i, entry := range hm.entries {
		if entry.ID == id {
			return &hm.entries[i], nil
		}
	}

	return nil, fmt.Errorf("entry not found: %s", id)
}

func (hm *HistoryManager) UpdateEntry(id string, updates map[string]interface{}) error {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	for i, entry := range hm.entries {
		if entry.ID == id {
			// Apply updates
			if notes, ok := updates["notes"].(string); ok {
				hm.entries[i].Notes = notes
			}
			if tags, ok := updates["tags"].([]string); ok {
				hm.entries[i].Tags = tags
			}

			return hm.persistEntry(hm.entries[i])
		}
	}

	return fmt.Errorf("entry not found: %s", id)
}

func (hm *HistoryManager) DeleteEntry(id string) error {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	for i, entry := range hm.entries {
		if entry.ID == id {
			// Remove from slice
			hm.entries = append(hm.entries[:i], hm.entries[i+1:]...)

			// Rebuild index
			hm.rebuildIndex()

			// Remove from disk
			os.Remove(hm.getEntryFilePath(id))

			return nil
		}
	}

	return fmt.Errorf("entry not found: %s", id)
}

func (hm *HistoryManager) Clear() error {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	hm.entries = make([]HistoryEntry, 0)
	hm.index = make(map[string]int)

	// Clear all files
	files, err := os.ReadDir(hm.dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
			os.Remove(filepath.Join(hm.dir, file.Name()))
		}
	}

	return nil
}

func (hm *HistoryManager) GetStats() HistoryStats {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	stats := HistoryStats{
		TotalScans:   len(hm.entries),
		TopVulnTypes: make(map[string]int),
	}

	var totalDuration time.Duration
	var vulnCount int
	urlVulnCount := make(map[string]int)

	for _, entry := range hm.entries {
		totalDuration += entry.Duration
		vulnCount += len(entry.Results)

		if entry.Timestamp.After(stats.LastScanTime) {
			stats.LastScanTime = entry.Timestamp
		}

		// Count vulns per URL
		urlVulnCount[entry.TargetURL] += len(entry.Results)

		// Count vuln types
		for _, result := range entry.Results {
			stats.TopVulnTypes[result.VulnType]++
		}
	}

	stats.TotalVulnsFound = vulnCount

	if len(hm.entries) > 0 {
		stats.AverageDuration = totalDuration / time.Duration(len(hm.entries))
	}

	// Find most vulnerable URL
	maxVulns := 0
	for url, count := range urlVulnCount {
		if count > maxVulns {
			maxVulns = count
			stats.MostVulnerableURL = url
		}
	}

	return stats
}

func (hm *HistoryManager) evictOldest() {
	if len(hm.entries) <= hm.maxEntries {
		return
	}

	// Remove oldest entry
	oldest := hm.entries[0]
	hm.entries = hm.entries[1:]

	// Update index
	delete(hm.index, oldest.TargetURL)

	// Remove from disk
	os.Remove(hm.getEntryFilePath(oldest.ID))
}

func (hm *HistoryManager) rebuildIndex() {
	hm.index = make(map[string]int)
	for i, entry := range hm.entries {
		hm.index[entry.TargetURL] = i
	}
}

func (hm *HistoryManager) loadHistory() error {
	files, err := os.ReadDir(hm.dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(hm.dir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var entry HistoryEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		hm.entries = append(hm.entries, entry)
		hm.index[entry.TargetURL] = len(hm.entries) - 1
	}

	// Sort by timestamp descending
	sort.Slice(hm.entries, func(i, j int) bool {
		return hm.entries[i].Timestamp.After(hm.entries[j].Timestamp)
	})

	return nil
}

func (hm *HistoryManager) persistEntry(entry HistoryEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	filePath := hm.getEntryFilePath(entry.ID)
	return os.WriteFile(filePath, data, 0644)
}

func (hm *HistoryManager) getEntryFilePath(id string) string {
	return filepath.Join(hm.dir, fmt.Sprintf("%s.json", id))
}

func generateEntryID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}

// Helper functions
func containsMatch(s, pattern string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(pattern))
}

func hasMinimumSeverity(results []*core.ScanResult, minSeverity string) bool {
	severityRanks := map[string]int{
		"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
	}

	minRank, exists := severityRanks[strings.ToUpper(minSeverity)]
	if !exists {
		return true
	}

	for _, r := range results {
		if rank, exists := severityRanks[strings.ToUpper(r.Severity)]; exists && rank >= minRank {
			return true
		}
	}

	return false
}

func hasAllTags(entryTags, queryTags []string) bool {
	tagSet := make(map[string]bool)
	for _, t := range entryTags {
		tagSet[t] = true
	}

	for _, qt := range queryTags {
		if !tagSet[qt] {
			return false
		}
	}

	return true
}

func getMaxSeverityRank(results []*core.ScanResult) int {
	severityRanks := map[string]int{
		"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5,
	}

	maxRank := 0
	for _, r := range results {
		if rank, exists := severityRanks[strings.ToUpper(r.Severity)]; exists && rank > maxRank {
			maxRank = rank
		}
	}

	return maxRank
}
