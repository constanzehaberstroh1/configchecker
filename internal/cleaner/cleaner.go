package cleaner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/configchecker/internal/logger"
)

// validPrefixes are the known protocol prefixes for v2ray configs
var validPrefixes = []string{
	"vmess://", "vless://", "trojan://", "ss://", "ssr://",
	"hysteria://", "hysteria2://", "hy2://", "tuic://", "wg://",
	"wireguard://",
}

// CleanConfigs reads configs from inputFile, removes duplicates and non-v2ray lines,
// writes cleaned configs back in place. Uses parallel workers for processing.
func CleanConfigs(ctx context.Context, configPath string, maxWorkers int, log *logger.Logger) (int64, error) {
	log.Info("Starting config cleaner...")
	log.Info("Reading configs from: %s", configPath)

	// Read all configs
	lines, err := readAllLines(configPath)
	if err != nil {
		return 0, fmt.Errorf("reading configs: %w", err)
	}
	log.Info("Total raw lines: %d", len(lines))

	if len(lines) == 0 {
		log.Warn("No configs found to clean")
		return 0, nil
	}

	tracker := logger.NewTracker("CLEAN", int64(len(lines)), log)

	// Process in parallel chunks
	type result struct {
		config string
		valid  bool
	}

	chunkSize := len(lines) / maxWorkers
	if chunkSize < 100 {
		chunkSize = 100
	}

	resultCh := make(chan result, 10000)
	var wg sync.WaitGroup

	// Worker that validates configs
	for i := 0; i < len(lines); i += chunkSize {
		end := i + chunkSize
		if end > len(lines) {
			end = len(lines)
		}
		chunk := lines[i:end]

		wg.Add(1)
		go func(batch []string) {
			defer wg.Done()
			for _, line := range batch {
				line = strings.TrimSpace(line)
				if isValidConfig(line) {
					resultCh <- result{config: line, valid: true}
					tracker.Inc(true)
				} else {
					tracker.Inc(false)
				}
			}
		}(chunk)
	}

	// Close channel when done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect and deduplicate
	seen := make(map[string]struct{})
	var unique []string
	var duplicates int64

	for r := range resultCh {
		if r.valid {
			if _, exists := seen[r.config]; !exists {
				seen[r.config] = struct{}{}
				unique = append(unique, r.config)
			} else {
				atomic.AddInt64(&duplicates, 1)
			}
		}
	}

	tracker.Log()
	log.Info("Cleaned: %d unique configs (removed %d duplicates, %d invalid lines)",
		len(unique), duplicates, int64(len(lines))-int64(len(unique))-duplicates)

	// Write back in place
	if err := writeLines(configPath, unique); err != nil {
		return 0, fmt.Errorf("writing cleaned configs: %w", err)
	}

	log.Info("Cleaned configs saved to: %s", configPath)
	return int64(len(unique)), nil
}

func isValidConfig(line string) bool {
	if len(line) < 6 {
		return false
	}
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func readAllLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024) // 2MB line buffer
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 256*1024)
	for _, line := range lines {
		w.WriteString(line)
		w.WriteString("\n")
	}
	return w.Flush()
}
