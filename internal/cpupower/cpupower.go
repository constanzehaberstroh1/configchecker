package cpupower

import (
	"math"
	"runtime"
	"sync/atomic"
	"time"
)

// Info holds CPU power analysis results
type Info struct {
	NumCores        int
	WorkersPerCore  int
	TotalWorkers    int
	BenchmarkScore  float64
}

// Detect analyzes CPU cores and benchmarks to determine optimal worker count.
// Workers per core will be between 50 and 200, scaled by CPU benchmark score.
func Detect() Info {
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	score := benchmark(cores)

	// Scale workers per core between 50 and 200 based on benchmark score
	// Score is normalized: higher score = more workers per core
	wpc := int(math.Round(50 + (150 * score)))
	if wpc < 50 {
		wpc = 50
	}
	if wpc > 200 {
		wpc = 200
	}

	return Info{
		NumCores:       cores,
		WorkersPerCore: wpc,
		TotalWorkers:   cores * wpc,
		BenchmarkScore: score,
	}
}

// benchmark runs a quick CPU stress test to gauge relative power.
// Returns a normalized score between 0.0 and 1.0.
func benchmark(cores int) float64 {
	const duration = 200 * time.Millisecond
	var ops int64

	done := make(chan struct{})

	for i := 0; i < cores; i++ {
		go func() {
			var local int64
			for {
				select {
				case <-done:
					atomic.AddInt64(&ops, local)
					return
				default:
					// Simple arithmetic workload
					x := 1.0
					for j := 0; j < 1000; j++ {
						x = x*1.0001 + 0.0001
					}
					local++
				}
			}
		}()
	}

	time.Sleep(duration)
	close(done)
	time.Sleep(10 * time.Millisecond) // let goroutines finish

	totalOps := atomic.LoadInt64(&ops)
	opsPerCore := float64(totalOps) / float64(cores)

	// Normalize: baseline ~500 ops/core in 200ms = low end, ~5000 = high end
	score := (opsPerCore - 500) / 4500
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}
