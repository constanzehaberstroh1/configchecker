package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/configchecker/internal/cleaner"
	"github.com/configchecker/internal/cpupower"
	"github.com/configchecker/internal/fetcher"
	"github.com/configchecker/internal/logger"
	"github.com/configchecker/internal/pipeline"
)

func main() {
	startTime := time.Now()

	// Get runner name from environment or use hostname
	runnerName := os.Getenv("RUNNER_NAME")
	if runnerName == "" {
		runnerName = os.Getenv("HOSTNAME")
	}
	if runnerName == "" {
		h, _ := os.Hostname()
		runnerName = h
	}
	if runnerName == "" {
		runnerName = "local"
	}
	// Sanitize runner name for filesystem
	runnerName = sanitizeName(runnerName)

	// Setup directories
	baseDir := "."
	logsDir := filepath.Join(baseDir, "logs")
	configsDir := filepath.Join(baseDir, "configs")
	// Runner-specific output directory
	outputDir := filepath.Join(configsDir, runnerName)

	// Initialize logger
	log, err := logger.Init(logsDir, runnerName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Info("╔══════════════════════════════════════════════════════════╗")
	log.Info("║           V2Ray Config Checker Pipeline                 ║")
	log.Info("╚══════════════════════════════════════════════════════════╝")
	log.Info("Runner: %s", runnerName)
	log.Info("Start time: %s", startTime.Format(time.RFC3339))
	log.Info("Log file: %s", log.FilePath())

	// Context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Warn("Received signal: %v — initiating graceful shutdown...", sig)
		cancel()
	}()

	// ═══════════════════════════════════════════════
	// Step 1: Detect CPU Power
	// ═══════════════════════════════════════════════
	log.Info("")
	log.Info("╔══ STEP 1: CPU Power Detection ══╗")
	cpuInfo := cpupower.Detect()
	log.Info("  CPU Cores: %d", cpuInfo.NumCores)
	log.Info("  Workers/Core: %d", cpuInfo.WorkersPerCore)
	log.Info("  Total Workers: %d", cpuInfo.TotalWorkers)
	log.Info("  Benchmark Score: %.2f", cpuInfo.BenchmarkScore)
	log.Info("╚═════════════════════════════════╝")

	// ═══════════════════════════════════════════════
	// Step 2: Fetch Subscriptions
	// ═══════════════════════════════════════════════
	log.Info("")
	log.Info("╔══ STEP 2: Fetch Subscriptions ══╗")
	subsFile := filepath.Join(baseDir, "subs.txt")
	if _, err := os.Stat(subsFile); os.IsNotExist(err) {
		log.Error("Subscription file not found: %s", subsFile)
		saveResultsOnError(log, outputDir, runnerName)
		os.Exit(1)
	}

	fetchWorkers := cpuInfo.TotalWorkers / 2
	if fetchWorkers < 10 {
		fetchWorkers = 10
	}
	if fetchWorkers > 200 {
		fetchWorkers = 200
	}

	totalFetched, err := fetcher.FetchAll(ctx, subsFile, configsDir, fetchWorkers, log)
	if err != nil {
		log.Error("Fetch failed: %v", err)
		saveResultsOnError(log, outputDir, runnerName)
		os.Exit(1)
	}
	log.Info("  Fetched: %d configs", totalFetched)
	log.Info("╚═══════════════════════════════════╝")

	// Check context
	if ctx.Err() != nil {
		log.Warn("Shutting down after fetch step")
		saveResultsOnError(log, outputDir, runnerName)
		return
	}

	// ═══════════════════════════════════════════════
	// Step 3: Clean & Deduplicate Configs
	// ═══════════════════════════════════════════════
	log.Info("")
	log.Info("╔══ STEP 3: Clean & Deduplicate ══╗")
	configsFile := filepath.Join(configsDir, "configs.txt")
	cleanWorkers := cpuInfo.TotalWorkers
	if cleanWorkers < 4 {
		cleanWorkers = 4
	}

	cleanCount, err := cleaner.CleanConfigs(ctx, configsFile, cleanWorkers, log)
	if err != nil {
		log.Error("Clean failed: %v", err)
		saveResultsOnError(log, outputDir, runnerName)
		os.Exit(1)
	}
	log.Info("  Clean configs: %d", cleanCount)
	log.Info("╚══════════════════════════════════╝")

	if ctx.Err() != nil {
		log.Warn("Shutting down after clean step")
		saveResultsOnError(log, outputDir, runnerName)
		return
	}

	// ═══════════════════════════════════════════════
	// Step 4: Quality Testing Pipeline
	// ═══════════════════════════════════════════════
	log.Info("")
	log.Info("╔══ STEP 4: Quality Testing Pipeline ══╗")

	pipeCfg := pipeline.Config{
		ConfigsFile:  configsFile,
		OutputDir:    outputDir,
		CPUInfo:      cpuInfo,
		PingTimeout:  20 * time.Second,
		SpeedTimeout: 30 * time.Second,
	}

	pipe := pipeline.NewPipeline(pipeCfg, log)
	healthyCount, err := pipe.Run(ctx)
	if err != nil {
		log.Error("Pipeline failed: %v", err)
		saveResultsOnError(log, outputDir, runnerName)
		// Don't exit — save whatever we have
	}
	log.Info("  Healthy configs: %d", healthyCount)
	log.Info("╚══════════════════════════════════════╝")

	// ═══════════════════════════════════════════════
	// Step 5: Handle large files (>100MB)
	// ═══════════════════════════════════════════════
	log.Info("")
	log.Info("╔══ STEP 5: File Size Check ══╗")
	workedFile := filepath.Join(outputDir, "worked.txt")
	handleLargeFiles(log, workedFile)
	log.Info("╚═════════════════════════════╝")

	// ═══════════════════════════════════════════════
	// Final Summary
	// ═══════════════════════════════════════════════
	elapsed := time.Since(startTime)
	log.Info("")
	log.Info("╔══════════════════════════════════════════════════════════╗")
	log.Info("║                    FINAL SUMMARY                       ║")
	log.Info("╠══════════════════════════════════════════════════════════╣")
	log.Info("║  Runner: %-45s ║", runnerName)
	log.Info("║  Total fetched configs: %-31d ║", totalFetched)
	log.Info("║  Unique clean configs:  %-31d ║", cleanCount)
	log.Info("║  Healthy tested configs:%-31d ║", healthyCount)
	log.Info("║  Time elapsed: %-39s ║", elapsed.Round(time.Second).String())
	log.Info("║  Output: %-45s ║", outputDir)
	log.Info("╚══════════════════════════════════════════════════════════╝")
}

// handleLargeFiles splits files larger than 95MB (leaving margin for git)
func handleLargeFiles(log *logger.Logger, filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("Output file does not exist: %s", filePath)
			return
		}
		log.Error("Cannot stat file: %v", err)
		return
	}

	maxSize := int64(95 * 1024 * 1024) // 95MB limit (5MB safety margin)
	fileSize := info.Size()
	log.Info("Output file size: %.2f MB", float64(fileSize)/(1024*1024))

	if fileSize <= maxSize {
		log.Info("File size is within GitHub limits")
		return
	}

	log.Warn("File exceeds 95MB limit, splitting into parts...")

	f, err := os.Open(filePath)
	if err != nil {
		log.Error("Cannot open file for splitting: %v", err)
		return
	}
	defer f.Close()

	dir := filepath.Dir(filePath)
	baseName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	ext := filepath.Ext(filePath)

	partNum := 1
	var currentSize int64
	var currentFile *os.File

	buf := make([]byte, 64*1024) // 64KB read buffer

	createPart := func() error {
		if currentFile != nil {
			currentFile.Close()
		}
		partPath := filepath.Join(dir, fmt.Sprintf("%s_part%d%s", baseName, partNum, ext))
		var err error
		currentFile, err = os.Create(partPath)
		if err != nil {
			return err
		}
		log.Info("Creating part: %s", partPath)
		currentSize = 0
		partNum++
		return nil
	}

	if err := createPart(); err != nil {
		log.Error("Cannot create first part: %v", err)
		return
	}
	defer func() {
		if currentFile != nil {
			currentFile.Close()
		}
	}()

	for {
		n, err := f.Read(buf)
		if n > 0 {
			if currentSize+int64(n) > maxSize {
				if createErr := createPart(); createErr != nil {
					log.Error("Cannot create part: %v", createErr)
					return
				}
			}
			currentFile.Write(buf[:n])
			currentSize += int64(n)
		}
		if err != nil {
			break
		}
	}

	// Remove original file to save space
	if currentFile != nil {
		currentFile.Close()
	}
	os.Remove(filePath)
	log.Info("Split into %d parts", partNum-1)
}

// saveResultsOnError ensures partial results are preserved on error
func saveResultsOnError(log *logger.Logger, outputDir, runnerName string) {
	log.Warn("Saving partial results due to error...")
	os.MkdirAll(outputDir, 0755)

	// Write a status file
	statusFile := filepath.Join(outputDir, "error_status.txt")
	content := fmt.Sprintf("Runner: %s\nTime: %s\nStatus: Error occurred during processing\n",
		runnerName, time.Now().Format(time.RFC3339))
	os.WriteFile(statusFile, []byte(content), 0644)
	log.Info("Error status saved to: %s", statusFile)
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ":", "_")
	// Remove any other problematic characters
	var result strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			result.WriteRune(c)
		}
	}
	s := result.String()
	if s == "" {
		s = "unknown_runner"
	}
	return s
}

// init checks for xray binary availability
func init() {
	if _, err := exec.LookPath("xray"); err != nil {
		// Don't fail silently - will be caught later in pipeline
		fmt.Fprintln(os.Stderr, "Warning: xray binary not found in PATH")
	}
}
