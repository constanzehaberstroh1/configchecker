package fetcher

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/configchecker/internal/logger"
)

// validV2rayPrefixes are the known protocol prefixes for v2ray configs
var validV2rayPrefixes = []string{
	"vmess://", "vless://", "trojan://", "ss://", "ssr://",
	"hysteria://", "hysteria2://", "hy2://", "tuic://", "wg://",
	"wireguard://",
}

// FetchAll reads subscription URLs from subsFile, fetches content in parallel,
// decodes base64 if needed, extracts v2ray configs, and saves to outputFile.
func FetchAll(ctx context.Context, subsFile, outputDir string, maxWorkers int, log *logger.Logger) (int64, error) {
	log.Info("Starting subscription fetcher...")
	log.Info("Reading subscription file: %s", subsFile)

	// Read subscription URLs
	urls, err := readLines(subsFile)
	if err != nil {
		return 0, fmt.Errorf("reading subs file: %w", err)
	}
	log.Info("Found %d subscription URLs", len(urls))

	// Filter out empty lines and comments
	var validURLs []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		validURLs = append(validURLs, u)
	}
	log.Info("Valid subscription URLs: %d", len(validURLs))

	if len(validURLs) == 0 {
		return 0, fmt.Errorf("no valid URLs found")
	}

	// Ensure output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return 0, fmt.Errorf("creating output dir: %w", err)
	}
	outputFile := filepath.Join(outputDir, "configs.txt")

	// Create output file
	out, err := os.Create(outputFile)
	if err != nil {
		return 0, fmt.Errorf("creating output file: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriterSize(out, 256*1024) // 256KB buffer
	defer writer.Flush()

	var (
		mu           sync.Mutex
		totalConfigs int64
		processed    int64
		success      int64
		failed       int64
	)

	tracker := logger.NewTracker("FETCH", int64(len(validURLs)), log)

	// Semaphore for concurrency control
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        maxWorkers,
			MaxIdleConnsPerHost: maxWorkers / 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	for i, url := range validURLs {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, u string) {
			defer wg.Done()
			defer func() { <-sem }()

			configs, fetchErr := fetchAndExtract(ctx, client, u, log)
			if fetchErr != nil {
				log.Warn("Failed to fetch [%d/%d] %s: %v", idx+1, len(validURLs), truncateURL(u), fetchErr)
				atomic.AddInt64(&failed, 1)
				tracker.Inc(false)
			} else {
				atomic.AddInt64(&success, 1)
				tracker.Inc(true)

				if len(configs) > 0 {
					mu.Lock()
					for _, c := range configs {
						writer.WriteString(c)
						writer.WriteString("\n")
					}
					mu.Unlock()
					atomic.AddInt64(&totalConfigs, int64(len(configs)))
				}
			}
			atomic.AddInt64(&processed, 1)

			// Log progress every 20 URLs or at the end
			p := atomic.LoadInt64(&processed)
			if p%20 == 0 || p == int64(len(validURLs)) {
				tracker.Log()
			}
		}(i, url)
	}

	wg.Wait()
	writer.Flush()

	total := atomic.LoadInt64(&totalConfigs)
	log.Info("Fetch complete: %d configs extracted from %d URLs (success: %d, failed: %d)",
		total, len(validURLs), atomic.LoadInt64(&success), atomic.LoadInt64(&failed))

	return total, nil
}

// fetchAndExtract fetches a single URL and extracts v2ray configs
func fetchAndExtract(ctx context.Context, client *http.Client, url string, log *logger.Logger) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (configchecker/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Read body with size limit of 50MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	content := string(body)
	return extractConfigs(content), nil
}

// extractConfigs tries to decode base64 first, then extracts v2ray config lines
func extractConfigs(content string) []string {
	var allConfigs []string

	// Try base64 decoding
	decoded := tryBase64Decode(content)
	if decoded != "" {
		allConfigs = append(allConfigs, extractV2rayLines(decoded)...)
	}

	// Also extract directly from original content
	allConfigs = append(allConfigs, extractV2rayLines(content)...)

	// Deduplicate within this batch
	seen := make(map[string]struct{})
	var unique []string
	for _, c := range allConfigs {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			unique = append(unique, c)
		}
	}

	return unique
}

// extractV2rayLines scans text line by line and extracts v2ray config lines
func extractV2rayLines(text string) []string {
	var configs []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isV2rayConfig(line) {
			configs = append(configs, line)
		}
	}
	return configs
}

// isV2rayConfig checks if a string starts with a known v2ray protocol prefix
func isV2rayConfig(s string) bool {
	for _, prefix := range validV2rayPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// tryBase64Decode attempts to decode a base64 encoded string
func tryBase64Decode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return ""
	}

	// Try standard base64
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(s)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}

	// Try raw (no padding) variants
	decoded, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}

	decoded, err = base64.RawURLEncoding.DecodeString(s)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}

	return ""
}

// readLines reads all lines from a file
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func truncateURL(u string) string {
	if len(u) > 80 {
		return u[:77] + "..."
	}
	return u
}
