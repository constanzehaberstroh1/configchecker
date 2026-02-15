package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/configchecker/internal/cleaner"
	"github.com/configchecker/internal/core"
	"github.com/configchecker/internal/cpupower"
	"github.com/configchecker/internal/fetcher"
	"github.com/configchecker/internal/logger"
	"github.com/configchecker/internal/pipeline"
)

// WorkerStatus tracks the state of a worker for the collector
type WorkerStatus struct {
	ChunkID       int     `json:"chunk_id"`
	RunnerName    string  `json:"runner_name"`
	Status        string  `json:"status"` // "complete", "partial", "error"
	TotalInChunk  int64   `json:"total_in_chunk"`
	Processed     int64   `json:"processed"`
	PingPass      int64   `json:"ping_pass"`
	PingFail      int64   `json:"ping_fail"`
	SpeedPass     int64   `json:"speed_pass"`
	SpeedFail     int64   `json:"speed_fail"`
	HealthyOutput int64   `json:"healthy_output"`
	Remaining     int64   `json:"remaining"`
	Error         string  `json:"error,omitempty"`
	StartedAt     string  `json:"started_at"`
	FinishedAt    string  `json:"finished_at"`
	DurationSecs  float64 `json:"duration_secs"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "fetch":
		cmdFetch()
	case "clean":
		cmdClean()
	case "split":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: configchecker split <chunk_count>")
			os.Exit(1)
		}
		n, _ := strconv.Atoi(os.Args[2])
		if n < 1 {
			n = 4
		}
		cmdSplit(n)
	case "test":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: configchecker test <chunk_file> <chunk_id>")
			os.Exit(1)
		}
		chunkID, _ := strconv.Atoi(os.Args[3])
		cmdTest(os.Args[2], chunkID)
	case "merge":
		cmdMerge()
	case "full":
		cmdFull()
	case "cores":
		cmdCores()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("V2Ray Config Checker Pipeline")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  fetch                    Fetch subscriptions and save raw configs")
	fmt.Println("  clean                    Deduplicate and validate configs")
	fmt.Println("  split <N>                Split configs into N chunks for workers")
	fmt.Println("  test <file> <id>         Run pipeline on a single chunk")
	fmt.Println("  merge                    Merge all worker results")
	fmt.Println("  full                     Run entire pipeline in one shot")
	fmt.Println("  cores                    List available proxy cores")
	fmt.Println("")
	fmt.Println("Environment:")
	fmt.Println("  PROXY_CORE=xray          Select proxy core (xray, singbox, mihomo, v2ray, shoes)")
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: fetch
// ═══════════════════════════════════════════════════════════════

func cmdFetch() {
	log := initLogger("master")
	defer log.Close()

	log.Info("╔══════════════════════════════════════╗")
	log.Info("║     MASTER: Fetch Subscriptions      ║")
	log.Info("╚══════════════════════════════════════╝")

	ctx, cancel := contextWithSignal()
	defer cancel()

	cpuInfo := cpupower.Detect()
	log.Info("CPU Cores: %d | Workers/Core: %d | Total Workers: %d",
		cpuInfo.NumCores, cpuInfo.WorkersPerCore, cpuInfo.TotalWorkers)

	subsFile := "subs.txt"
	configsDir := "configs"

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
		os.Exit(1)
	}

	log.Info("✅ Fetch complete: %d configs saved to configs/configs.txt", totalFetched)
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: clean
// ═══════════════════════════════════════════════════════════════

func cmdClean() {
	log := initLogger("master")
	defer log.Close()

	log.Info("╔══════════════════════════════════════╗")
	log.Info("║     MASTER: Clean & Deduplicate      ║")
	log.Info("╚══════════════════════════════════════╝")

	ctx, cancel := contextWithSignal()
	defer cancel()

	cpuInfo := cpupower.Detect()
	configsFile := filepath.Join("configs", "configs.txt")

	cleanCount, err := cleaner.CleanConfigs(ctx, configsFile, cpuInfo.TotalWorkers, log)
	if err != nil {
		log.Error("Clean failed: %v", err)
		os.Exit(1)
	}

	log.Info("✅ Clean complete: %d unique configs", cleanCount)

	// Output for GitHub Actions
	if ghOutput := os.Getenv("GITHUB_OUTPUT"); ghOutput != "" {
		f, _ := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644)
		if f != nil {
			fmt.Fprintf(f, "total_configs=%d\n", cleanCount)
			f.Close()
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: split
// ═══════════════════════════════════════════════════════════════

func cmdSplit(chunkCount int) {
	log := initLogger("master")
	defer log.Close()

	log.Info("╔══════════════════════════════════════╗")
	log.Info("║     MASTER: Split into %d Chunks     ║", chunkCount)
	log.Info("╚══════════════════════════════════════╝")

	configsFile := filepath.Join("configs", "configs.txt")
	chunksDir := "chunks"
	os.MkdirAll(chunksDir, 0755)

	// Read all configs
	lines, err := readLines(configsFile)
	if err != nil {
		log.Error("Cannot read configs: %v", err)
		os.Exit(1)
	}

	totalConfigs := len(lines)
	log.Info("Total configs to split: %d", totalConfigs)

	if totalConfigs == 0 {
		log.Error("No configs to split")
		os.Exit(1)
	}

	// Calculate chunk sizes
	chunkSize := totalConfigs / chunkCount
	remainder := totalConfigs % chunkCount

	offset := 0
	for i := 0; i < chunkCount; i++ {
		size := chunkSize
		if i < remainder {
			size++ // distribute remainder evenly
		}

		chunkFile := filepath.Join(chunksDir, fmt.Sprintf("chunk_%d.txt", i))
		if err := writeLines(chunkFile, lines[offset:offset+size]); err != nil {
			log.Error("Writing chunk %d: %v", i, err)
			os.Exit(1)
		}

		log.Info("  Chunk %d: %d configs → %s", i, size, chunkFile)
		offset += size
	}

	log.Info("✅ Split complete: %d configs → %d chunks", totalConfigs, chunkCount)

	// Output matrix for GitHub Actions
	if ghOutput := os.Getenv("GITHUB_OUTPUT"); ghOutput != "" {
		f, _ := os.OpenFile(ghOutput, os.O_APPEND|os.O_WRONLY, 0644)
		if f != nil {
			// Build chunk_id array
			ids := make([]int, chunkCount)
			for i := range ids {
				ids[i] = i
			}
			matrixJSON, _ := json.Marshal(map[string][]int{"chunk_id": ids})
			fmt.Fprintf(f, "matrix=%s\n", string(matrixJSON))
			fmt.Fprintf(f, "total_configs=%d\n", totalConfigs)
			fmt.Fprintf(f, "chunk_count=%d\n", chunkCount)
			f.Close()
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: test (worker mode)
// ═══════════════════════════════════════════════════════════════

func cmdTest(chunkFile string, chunkID int) {
	startTime := time.Now()

	runnerName := getRunnerName()
	log := initLogger(fmt.Sprintf("worker_%d_%s", chunkID, runnerName))
	defer log.Close()

	log.Info("╔══════════════════════════════════════════════╗")
	log.Info("║     WORKER %d: Testing Configs               ║", chunkID)
	log.Info("║     Runner: %-32s ║", runnerName)
	log.Info("╚══════════════════════════════════════════════╝")

	ctx, cancel := contextWithSignal()
	defer cancel()

	cpuInfo := cpupower.Detect()
	log.Info("CPU Cores: %d | Workers/Core: %d | Total Workers: %d",
		cpuInfo.NumCores, cpuInfo.WorkersPerCore, cpuInfo.TotalWorkers)

	// Check chunk file exists
	if _, err := os.Stat(chunkFile); os.IsNotExist(err) {
		log.Error("Chunk file not found: %s", chunkFile)
		writeWorkerStatus(chunkID, runnerName, "error", 0, 0, 0, 0, 0, 0, 0, 0,
			"chunk file not found", startTime)
		os.Exit(1)
	}

	// Count lines in chunk
	chunkLines, _ := readLines(chunkFile)
	totalInChunk := int64(len(chunkLines))
	log.Info("Chunk %d contains %d configs", chunkID, totalInChunk)

	// Output directory for this worker
	outputDir := filepath.Join("results", fmt.Sprintf("worker_%d", chunkID))
	os.MkdirAll(outputDir, 0755)

	// Run the pipeline
	pipeCfg := pipeline.Config{
		ConfigsFile:  chunkFile,
		OutputDir:    outputDir,
		CPUInfo:      cpuInfo,
		PingTimeout:  20 * time.Second,
		SpeedTimeout: 30 * time.Second,
	}

	// Create proxy core tester
	tester := createTester(log)

	pipe := pipeline.NewPipeline(pipeCfg, tester, log)

	// Wrap in error recovery
	var healthyCount int64
	var pipeErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				pipeErr = fmt.Errorf("panic recovered: %v", r)
				log.Error("PANIC in pipeline: %v", r)
			}
		}()
		healthyCount, pipeErr = pipe.Run(ctx)
	}()

	duration := time.Since(startTime)
	status := "complete"
	errMsg := ""

	if pipeErr != nil {
		status = "partial"
		errMsg = pipeErr.Error()
		log.Error("Pipeline error (partial results saved): %v", pipeErr)
	}

	if ctx.Err() != nil {
		status = "partial"
		errMsg = "context cancelled: " + ctx.Err().Error()
	}

	// Write worker status
	writeWorkerStatus(chunkID, runnerName, status, totalInChunk,
		pipe.GetProcessedCount(), pipe.GetPingSuccess(), pipe.GetPingFailed(),
		pipe.GetSpeedSuccess(), pipe.GetSpeedFailed(), healthyCount,
		totalInChunk-pipe.GetProcessedCount(), errMsg, startTime)

	log.Info("═══════════════════════════════════════════")
	log.Info("  WORKER %d SUMMARY", chunkID)
	log.Info("  Status: %s", status)
	log.Info("  Chunk size: %d configs", totalInChunk)
	log.Info("  Processed: %d", pipe.GetProcessedCount())
	log.Info("  Healthy output: %d", healthyCount)
	log.Info("  Duration: %s", duration.Round(time.Second))
	if errMsg != "" {
		log.Info("  Error: %s", errMsg)
	}
	log.Info("═══════════════════════════════════════════")
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: merge (collector mode)
// ═══════════════════════════════════════════════════════════════

func cmdMerge() {
	log := initLogger("collector")
	defer log.Close()

	log.Info("╔══════════════════════════════════════════════╗")
	log.Info("║     COLLECTOR: Merge Worker Results          ║")
	log.Info("╚══════════════════════════════════════════════╝")

	runnerName := getRunnerName()
	outputDir := filepath.Join("configs", sanitizeName(runnerName))
	os.MkdirAll(outputDir, 0755)

	resultsDir := "results"
	var allHealthy []string
	var totalProcessed, totalHealthy, totalFailed int64
	var workerStatuses []WorkerStatus

	// Scan for worker results
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		log.Error("Cannot read results directory: %v", err)
		// Try to save what we have
		writeEmptyResult(outputDir, log)
		os.Exit(1)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		workerDir := filepath.Join(resultsDir, entry.Name())

		// Read worker status
		statusFile := filepath.Join(workerDir, "status.json")
		if data, err := os.ReadFile(statusFile); err == nil {
			var ws WorkerStatus
			if json.Unmarshal(data, &ws) == nil {
				workerStatuses = append(workerStatuses, ws)
				totalProcessed += ws.Processed
				totalHealthy += ws.HealthyOutput
				totalFailed += ws.PingFail + ws.SpeedFail

				log.Info("  Worker %d (%s): status=%s, processed=%d, healthy=%d, remaining=%d",
					ws.ChunkID, ws.RunnerName, ws.Status, ws.Processed, ws.HealthyOutput, ws.Remaining)

				if ws.Status == "error" || ws.Status == "partial" {
					log.Warn("  ⚠️ Worker %d had issues: %s", ws.ChunkID, ws.Error)
				}
			}
		}

		// Read worked configs
		workedFile := filepath.Join(workerDir, "worked.txt")
		if lines, err := readLines(workedFile); err == nil {
			allHealthy = append(allHealthy, lines...)
			log.Info("  → Collected %d healthy configs from %s", len(lines), entry.Name())
		}
	}

	log.Info("")
	log.Info("╔══════════════════════════════════════════════╗")
	log.Info("║            MERGE SUMMARY                     ║")
	log.Info("╠══════════════════════════════════════════════╣")
	log.Info("║  Workers reported: %-25d ║", len(workerStatuses))
	log.Info("║  Total processed:  %-25d ║", totalProcessed)
	log.Info("║  Total healthy:    %-25d ║", len(allHealthy))
	log.Info("║  Total failed:     %-25d ║", totalFailed)
	log.Info("╚══════════════════════════════════════════════╝")

	// Deduplicate merged results (workers have unique chunks, but just in case)
	seen := make(map[string]struct{})
	var unique []string
	for _, c := range allHealthy {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, exists := seen[c]; !exists {
			seen[c] = struct{}{}
			unique = append(unique, c)
		}
	}

	log.Info("After dedup: %d unique healthy configs", len(unique))

	// Sort by speed (fastest first)
	log.Info("Sorting configs by speed (fastest first)...")
	unique = sortBySpeed(unique)
	if len(unique) > 0 {
		topSpeed := extractSpeed(unique[0])
		botSpeed := extractSpeed(unique[len(unique)-1])
		log.Info("Speed range: %.0f KB/s (fastest) → %.0f KB/s (slowest)", topSpeed, botSpeed)
	}

	// Write final output
	outputFile := filepath.Join(outputDir, "worked.txt")
	if err := writeLines(outputFile, unique); err != nil {
		log.Error("Writing merged output: %v", err)
		os.Exit(1)
	}

	// Handle large files (>95MB)
	handleLargeFiles(log, outputFile)

	// Write summary JSON
	summaryFile := filepath.Join(outputDir, "summary.json")
	summary := map[string]interface{}{
		"timestamp":       time.Now().Format(time.RFC3339),
		"runner":          runnerName,
		"total_processed": totalProcessed,
		"total_healthy":   len(unique),
		"total_failed":    totalFailed,
		"workers":         workerStatuses,
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(summaryFile, summaryJSON, 0644)

	log.Info("✅ Merge complete: %d healthy configs → %s", len(unique), outputFile)
}

// ═══════════════════════════════════════════════════════════════
// COMMAND: full (original all-in-one mode)
// ═══════════════════════════════════════════════════════════════

func cmdFull() {
	startTime := time.Now()
	runnerName := getRunnerName()
	log := initLogger(runnerName)
	defer log.Close()

	log.Info("╔══════════════════════════════════════════════════════════╗")
	log.Info("║           V2Ray Config Checker Pipeline (Full)          ║")
	log.Info("╚══════════════════════════════════════════════════════════╝")
	log.Info("Runner: %s", runnerName)

	ctx, cancel := contextWithSignal()
	defer cancel()

	outputDir := filepath.Join("configs", sanitizeName(runnerName))

	// Step 1: CPU Detection
	cpuInfo := cpupower.Detect()
	log.Info("[STEP 1] CPU: %d cores, %d workers/core, %d total",
		cpuInfo.NumCores, cpuInfo.WorkersPerCore, cpuInfo.TotalWorkers)

	// Step 2: Fetch
	log.Info("[STEP 2] Fetching subscriptions...")
	fetchWorkers := cpuInfo.TotalWorkers / 2
	if fetchWorkers < 10 {
		fetchWorkers = 10
	}
	if fetchWorkers > 200 {
		fetchWorkers = 200
	}
	totalFetched, err := fetcher.FetchAll(ctx, "subs.txt", "configs", fetchWorkers, log)
	if err != nil {
		log.Error("Fetch failed: %v", err)
		saveErrorStatus(outputDir, runnerName, err)
		os.Exit(1)
	}

	// Step 3: Clean
	log.Info("[STEP 3] Cleaning configs...")
	configsFile := filepath.Join("configs", "configs.txt")
	cleanCount, err := cleaner.CleanConfigs(ctx, configsFile, cpuInfo.TotalWorkers, log)
	if err != nil {
		log.Error("Clean failed: %v", err)
		saveErrorStatus(outputDir, runnerName, err)
		os.Exit(1)
	}

	// Step 4: Pipeline
	log.Info("[STEP 4] Running quality test pipeline...")
	pipeCfg := pipeline.Config{
		ConfigsFile:  configsFile,
		OutputDir:    outputDir,
		CPUInfo:      cpuInfo,
		PingTimeout:  20 * time.Second,
		SpeedTimeout: 30 * time.Second,
	}
	tester := createTester(log)
	pipe := pipeline.NewPipeline(pipeCfg, tester, log)
	healthyCount, _ := pipe.Run(ctx)

	// Step 5: File check
	handleLargeFiles(log, filepath.Join(outputDir, "worked.txt"))

	elapsed := time.Since(startTime)
	log.Info("╔═══════════════════ FINAL SUMMARY ═══════════════════╗")
	log.Info("║  Fetched: %-42d ║", totalFetched)
	log.Info("║  Cleaned: %-42d ║", cleanCount)
	log.Info("║  Healthy: %-42d ║", healthyCount)
	log.Info("║  Time:    %-42s ║", elapsed.Round(time.Second))
	log.Info("╚═════════════════════════════════════════════════════╝")
}

// ═══════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════

// createTester creates a proxy tester using the selected core
func createTester(log *logger.Logger) core.Tester {
	coreName := os.Getenv("PROXY_CORE")
	if coreName == "" {
		coreName = "xray" // default
	}

	c, err := core.GetCore(coreName)
	if err != nil {
		log.Error("Unknown core '%s': %v", coreName, err)
		log.Info("Available cores: %s", core.ListCoreNames())
		os.Exit(1)
	}

	if !c.IsAvailable() {
		log.Warn("Core '%s' binary '%s' not found in PATH", coreName, c.BinaryName())
		log.Warn("Continuing anyway — tests will fail if binary is missing")
	}

	log.Info("Using proxy core: %s (binary: %s, available: %v)",
		c.Name(), c.BinaryName(), c.IsAvailable())
	log.Info("Supported protocols: %v", c.SupportedProtocols())

	return core.NewManager(c, log)
}

func cmdCores() {
	fmt.Println("Available Proxy Cores:")
	fmt.Println("")
	for _, info := range core.ListCores() {
		avail := "❌"
		if info.Available {
			avail = "✅"
		}
		fmt.Printf("  %s %-10s  binary: %-12s  %s\n", avail, info.Name, info.Binary, strings.Join(info.Protocols, ", "))
	}
	fmt.Println("")
	fmt.Println("Set PROXY_CORE env var to select: PROXY_CORE=singbox ./configchecker test ...")
}

func initLogger(prefix string) *logger.Logger {
	logsDir := "logs"
	log, err := logger.Init(logsDir, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logger init failed: %v\n", err)
		os.Exit(1)
	}
	return log
}

func contextWithSignal() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	return ctx, cancel
}

func getRunnerName() string {
	name := os.Getenv("RUNNER_NAME")
	if name == "" {
		name, _ = os.Hostname()
	}
	if name == "" {
		name = "local"
	}
	return sanitizeName(name)
}

func sanitizeName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()
	if s == "" {
		return "unknown"
	}
	return s
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	os.MkdirAll(filepath.Dir(path), 0755)
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

func writeWorkerStatus(chunkID int, runner, status string,
	total, processed, pingPass, pingFail, speedPass, speedFail, healthy, remaining int64,
	errMsg string, startTime time.Time) {

	ws := WorkerStatus{
		ChunkID:       chunkID,
		RunnerName:    runner,
		Status:        status,
		TotalInChunk:  total,
		Processed:     processed,
		PingPass:      pingPass,
		PingFail:      pingFail,
		SpeedPass:     speedPass,
		SpeedFail:     speedFail,
		HealthyOutput: healthy,
		Remaining:     remaining,
		Error:         errMsg,
		StartedAt:     startTime.Format(time.RFC3339),
		FinishedAt:    time.Now().Format(time.RFC3339),
		DurationSecs:  time.Since(startTime).Seconds(),
	}

	outputDir := filepath.Join("results", fmt.Sprintf("worker_%d", chunkID))
	os.MkdirAll(outputDir, 0755)

	data, _ := json.MarshalIndent(ws, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "status.json"), data, 0644)
}

func writeEmptyResult(outputDir string, log *logger.Logger) {
	os.MkdirAll(outputDir, 0755)
	os.WriteFile(filepath.Join(outputDir, "worked.txt"), []byte(""), 0644)
	log.Warn("Empty result file created")
}

func saveErrorStatus(outputDir, runnerName string, err error) {
	os.MkdirAll(outputDir, 0755)
	content := fmt.Sprintf("Runner: %s\nTime: %s\nError: %v\n",
		runnerName, time.Now().Format(time.RFC3339), err)
	os.WriteFile(filepath.Join(outputDir, "error_status.txt"), []byte(content), 0644)
}

func handleLargeFiles(log *logger.Logger, filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return
	}

	maxSize := int64(95 * 1024 * 1024) // 95MB
	if info.Size() <= maxSize {
		log.Info("Output file size: %.2f MB (within limits)", float64(info.Size())/(1024*1024))
		return
	}

	log.Warn("File %.2f MB exceeds 95MB limit, splitting...", float64(info.Size())/(1024*1024))

	f, err := os.Open(filePath)
	if err != nil {
		log.Error("Cannot open for splitting: %v", err)
		return
	}
	defer f.Close()

	dir := filepath.Dir(filePath)
	base := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	ext := filepath.Ext(filePath)

	partNum := 1
	var currentSize int64
	var currentFile *os.File
	buf := make([]byte, 64*1024)

	newPart := func() error {
		if currentFile != nil {
			currentFile.Close()
		}
		partPath := filepath.Join(dir, fmt.Sprintf("%s_part%d%s", base, partNum, ext))
		var err error
		currentFile, err = os.Create(partPath)
		if err != nil {
			return err
		}
		log.Info("Creating: %s", partPath)
		currentSize = 0
		partNum++
		return nil
	}

	if err := newPart(); err != nil {
		log.Error("Cannot create part: %v", err)
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
				if err := newPart(); err != nil {
					log.Error("Cannot create part: %v", err)
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

	if currentFile != nil {
		currentFile.Close()
	}
	os.Remove(filePath)
	log.Info("Split into %d parts", partNum-1)
}

// ═══════════════════════════════════════════════════════════════
// Speed Sorting
// ═══════════════════════════════════════════════════════════════

var speedPattern = regexp.MustCompile(`xray:(\d+(?:\.\d+)?)KB/s`)

// sortBySpeed sorts config lines by their xray speed tag, fastest first
func sortBySpeed(configs []string) []string {
	sort.SliceStable(configs, func(i, j int) bool {
		return extractSpeed(configs[i]) > extractSpeed(configs[j])
	})
	return configs
}

// extractSpeed pulls the speed value from a config's remark/tag
func extractSpeed(config string) float64 {
	// For vmess:// configs, decode the base64 JSON and check "ps" field
	if strings.HasPrefix(config, "vmess://") {
		raw := strings.TrimPrefix(config, "vmess://")
		if data, err := tryB64Decode(raw); err == nil {
			var vmess map[string]interface{}
			if json.Unmarshal(data, &vmess) == nil {
				if ps, ok := vmess["ps"].(string); ok {
					if m := speedPattern.FindStringSubmatch(ps); len(m) > 1 {
						v, _ := strconv.ParseFloat(m[1], 64)
						return v
					}
				}
			}
		}
		return 0
	}

	// For URI-style configs, speed is in the fragment (#...xray:123KB/s)
	hashIdx := strings.LastIndex(config, "#")
	if hashIdx >= 0 {
		fragment := config[hashIdx+1:]
		decoded, err := url.QueryUnescape(fragment)
		if err != nil {
			decoded = fragment
		}
		if m := speedPattern.FindStringSubmatch(decoded); len(m) > 1 {
			v, _ := strconv.ParseFloat(m[1], 64)
			return v
		}
	}

	return 0
}

func tryB64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")

	padded := s
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}

	if data, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return data, nil
	}
	if data, err := base64.URLEncoding.DecodeString(padded); err == nil {
		return data, nil
	}
	if data, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
