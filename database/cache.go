package database

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/youwannahackme/originstrike/core"
)

type Cache struct {
	dir         string
	maxSize     int64 // maximum cache size in bytes
	currentSize int64
	ttl         time.Duration
	entries     map[string]*CacheEntry
	mutex       sync.RWMutex
	compression bool
}

type CacheEntry struct {
	Key       string                 `json:"key"`
	Data      []*core.ScanResult     `json:"data"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Size      int64                  `json:"size"`
	Hits      int64                  `json:"hits"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type CacheStats struct {
	TotalEntries   int     `json:"total_entries"`
	TotalHits      int64   `json:"total_hits"`
	TotalMisses    int64   `json:"total_misses"`
	HitRate        float64 `json:"hit_rate"`
	CurrentSize    int64   `json:"current_size_bytes"`
	MaxSize        int64   `json:"max_size_bytes"`
	ExpiredEntries int     `json:"expired_entries"`
}

func NewCache(cacheDir string, maxSizeMB int, ttlHours int) (*Cache, error) {
	// Create cache directory if not exists
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &Cache{
		dir:         cacheDir,
		maxSize:     int64(maxSizeMB) * 1024 * 1024,
		ttl:         time.Duration(ttlHours) * time.Hour,
		entries:     make(map[string]*CacheEntry),
		compression: true,
	}

	// Load existing cache from disk
	if err := cache.loadFromDisk(); err != nil {
		// Non-fatal, just log warning
		fmt.Printf("Warning: Could not load cache from disk: %v\n", err)
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache, nil
}

func (c *Cache) Get(key string) ([]*core.ScanResult, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		c.currentSize -= entry.Size
		return nil, false
	}

	// Update hit count
	entry.Hits++

	return entry.Data, true
}

func (c *Cache) Set(key string, results []*core.ScanResult, metadata map[string]interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Serialize data
	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to serialize cache data: %w", err)
	}

	entry := &CacheEntry{
		Key:       key,
		Data:      results,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(c.ttl),
		Size:      int64(len(data)),
		Hits:      0,
		Metadata:  metadata,
	}

	// Check if updating existing entry
	if existing, exists := c.entries[key]; exists {
		c.currentSize -= existing.Size
	}

	// Check size limit
	if c.currentSize+entry.Size > c.maxSize {
		c.evictLRU(int64(c.maxSize - entry.Size))
	}

	c.entries[key] = entry
	c.currentSize += entry.Size

	// Persist to disk asynchronously
	go c.persistToDisk(key, entry)

	return nil
}

func (c *Cache) Delete(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return false
	}

	delete(c.entries, key)
	c.currentSize -= entry.Size

	// Remove from disk
	os.Remove(c.getFilePath(key))

	return true
}

func (c *Cache) Clear() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.currentSize = 0

	// Clear disk cache
	files, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() {
			os.Remove(filepath.Join(c.dir, file.Name()))
		}
	}

	return nil
}

func (c *Cache) GetStats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stats := CacheStats{
		TotalEntries: len(c.entries),
		CurrentSize:  c.currentSize,
		MaxSize:      c.maxSize,
	}

	var totalHits, totalMisses int64
	var expiredCount int

	now := time.Now()
	for _, entry := range c.entries {
		totalHits += entry.Hits

		if now.After(entry.ExpiresAt) {
			expiredCount++
		}
	}

	stats.TotalHits = totalHits
	stats.ExpiredEntries = expiredCount

	if totalHits+totalMisses > 0 {
		stats.HitRate = float64(totalHits) / float64(totalHits+totalMisses) * 100
	}

	return stats
}

func (c *Cache) evictLRU(requiredSpace int64) {
	// Sort entries by last access time (hit count as proxy)
	type kv struct {
		key   string
		entry *CacheEntry
	}

	var sorted []kv
	for k, v := range c.entries {
		sorted = append(sorted, kv{k, v})
	}

	// Simple sort by hits (ascending - LRU approximation)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].entry.Hits > sorted[j].entry.Hits {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Evict until we have enough space
	for _, item := range sorted {
		if c.currentSize <= requiredSpace {
			break
		}

		delete(c.entries, item.key)
		c.currentSize -= item.entry.Size
		os.Remove(c.getFilePath(item.key))
	}
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpired()
	}
}

func (c *Cache) cleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			c.currentSize -= entry.Size
			os.Remove(c.getFilePath(key))
		}
	}
}

func (c *Cache) persistToDisk(key string, entry *CacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	filePath := c.getFilePath(key)
	return os.WriteFile(filePath, data, 0644)
}

func (c *Cache) loadFromDisk() error {
	files, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}

	count := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(c.dir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var entry CacheEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		// Skip expired entries
		if time.Now().After(entry.ExpiresAt) {
			os.Remove(filePath)
			continue
		}

		c.entries[entry.Key] = &entry
		c.currentSize += entry.Size
		count++
	}

	return nil
}

func (c *Cache) getFilePath(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, fmt.Sprintf("%x.cache", hash))
}

// Generate cache key from scan parameters
func GenerateCacheKey(url, origin, method string) string {
	key := fmt.Sprintf("%s|%s|%s|%d", url, origin, method, time.Now().Unix()/3600) // Hourly granularity
	return key
}
