package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Logger provides thread-safe logging to both stdout and a log file.
type Logger struct {
	mu       sync.Mutex
	fileLog  *log.Logger
	stdLog   *log.Logger
	file     *os.File
	filePath string
}

var globalLogger *Logger
var once sync.Once

// Init initializes the global logger. Creates logs folder and log file
// with pattern: logs/<runnerName>_YYYY-MM-DD_HH-MM-SS.txt
func Init(logsDir, runnerName string) (*Logger, error) {
	var err error
	once.Do(func() {
		err = os.MkdirAll(logsDir, 0755)
		if err != nil {
			return
		}

		timestamp := time.Now().Format("2006-01-02_15-04-05")
		fileName := fmt.Sprintf("%s_%s.txt", runnerName, timestamp)
		filePath := filepath.Join(logsDir, fileName)

		f, ferr := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if ferr != nil {
			err = ferr
			return
		}

		multiWriter := io.MultiWriter(os.Stdout, f)
		globalLogger = &Logger{
			fileLog:  log.New(f, "", log.LstdFlags|log.Lmicroseconds),
			stdLog:   log.New(multiWriter, "", log.LstdFlags|log.Lmicroseconds),
			file:     f,
			filePath: filePath,
		}
	})
	return globalLogger, err
}

// Get returns the global logger. Must call Init first.
func Get() *Logger {
	return globalLogger
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf("[INFO] "+format, args...)
	l.mu.Lock()
	l.stdLog.Println(msg)
	l.mu.Unlock()
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf("[WARN] "+format, args...)
	l.mu.Lock()
	l.stdLog.Println(msg)
	l.mu.Unlock()
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf("[ERROR] "+format, args...)
	l.mu.Lock()
	l.stdLog.Println(msg)
	l.mu.Unlock()
}

// Progress logs progress information
func (l *Logger) Progress(step string, processed, total, success, failed int64) {
	pct := float64(0)
	if total > 0 {
		pct = float64(processed) / float64(total) * 100
	}
	l.Info("[%s] Progress: %.1f%% (%d/%d) | Success: %d | Failed: %d",
		step, pct, processed, total, success, failed)
}

// Close flushes and closes the log file
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Sync()
		l.file.Close()
	}
}

// FilePath returns the log file path
func (l *Logger) FilePath() string {
	return l.filePath
}

// ProgressTracker provides atomic counters for tracking progress
type ProgressTracker struct {
	Total     int64
	Processed int64
	Success   int64
	Failed    int64
	Step      string
	logger    *Logger
}

// NewTracker creates a new progress tracker
func NewTracker(step string, total int64, logger *Logger) *ProgressTracker {
	return &ProgressTracker{
		Total:  total,
		Step:   step,
		logger: logger,
	}
}

// Inc increments processed and success/failed atomically
func (pt *ProgressTracker) Inc(success bool) {
	atomic.AddInt64(&pt.Processed, 1)
	if success {
		atomic.AddInt64(&pt.Success, 1)
	} else {
		atomic.AddInt64(&pt.Failed, 1)
	}
}

// Log emits current progress
func (pt *ProgressTracker) Log() {
	pt.logger.Progress(pt.Step,
		atomic.LoadInt64(&pt.Processed),
		atomic.LoadInt64(&pt.Total),
		atomic.LoadInt64(&pt.Success),
		atomic.LoadInt64(&pt.Failed),
	)
}
