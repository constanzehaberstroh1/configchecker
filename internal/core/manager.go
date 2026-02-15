package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/configchecker/internal/logger"
)

// Manager handles proxy testing using any Core implementation
type Manager struct {
	core        Core
	log         *logger.Logger
	portCounter int64
}

// NewManager creates a new Manager with the specified core
func NewManager(c Core, log *logger.Logger) *Manager {
	return &Manager{
		core:        c,
		log:         log,
		portCounter: 30000,
	}
}

func (m *Manager) GetCoreName() string   { return m.core.Name() }
func (m *Manager) GetBinaryPath() string { return m.core.BinaryName() }

// PingConfig tests proxy connectivity (latency) via generate_204
func (m *Manager) PingConfig(ctx context.Context, configLine string, timeout time.Duration) (int64, error) {
	pc, err := ParseURI(configLine)
	if err != nil {
		return 0, fmt.Errorf("parse config: %w", err)
	}

	if !m.core.SupportsProtocol(pc.Protocol) {
		return 0, fmt.Errorf("core %s does not support protocol %s", m.core.Name(), pc.Protocol)
	}

	port := int(atomic.AddInt64(&m.portCounter, 1))
	if port > 60000 {
		atomic.StoreInt64(&m.portCounter, 30000)
		port = 30000
	}

	// Generate config
	configData, err := m.core.GenerateConfig(pc, port)
	if err != nil {
		return 0, fmt.Errorf("generate config: %w", err)
	}

	// Write temp config file
	configFile := filepath.Join(os.TempDir(), fmt.Sprintf("proxy_ping_%d.json", port))
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		return 0, fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(configFile)

	// Start proxy
	cmdCtx, cmdCancel := context.WithTimeout(ctx, timeout)
	defer cmdCancel()

	args := m.core.RunArgs(configFile)
	cmd := exec.CommandContext(cmdCtx, m.core.BinaryName(), args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start %s: %w", m.core.Name(), err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for proxy to be ready
	if !waitForPort(port, 5*time.Second) {
		return 0, fmt.Errorf("proxy not ready on port %d", port)
	}

	// Test connectivity
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(cmdCtx, "GET", "https://www.google.com/generate_204", nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connectivity test: %w", err)
	}
	defer resp.Body.Close()

	latency := time.Since(start).Milliseconds()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return latency, nil
}

// SpeedTest measures download speed through the proxy
func (m *Manager) SpeedTest(ctx context.Context, configLine string, timeout time.Duration) (float64, int64, error) {
	pc, err := ParseURI(configLine)
	if err != nil {
		return 0, 0, fmt.Errorf("parse config: %w", err)
	}

	if !m.core.SupportsProtocol(pc.Protocol) {
		return 0, 0, fmt.Errorf("core %s does not support protocol %s", m.core.Name(), pc.Protocol)
	}

	port := int(atomic.AddInt64(&m.portCounter, 1))
	if port > 60000 {
		atomic.StoreInt64(&m.portCounter, 30000)
		port = 30000
	}

	configData, err := m.core.GenerateConfig(pc, port)
	if err != nil {
		return 0, 0, fmt.Errorf("generate config: %w", err)
	}

	configFile := filepath.Join(os.TempDir(), fmt.Sprintf("proxy_speed_%d.json", port))
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		return 0, 0, fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(configFile)

	cmdCtx, cmdCancel := context.WithTimeout(ctx, timeout)
	defer cmdCancel()

	args := m.core.RunArgs(configFile)
	cmd := exec.CommandContext(cmdCtx, m.core.BinaryName(), args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("start %s: %w", m.core.Name(), err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	if !waitForPort(port, 5*time.Second) {
		return 0, 0, fmt.Errorf("proxy not ready on port %d", port)
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	testURL := "https://cachefly.cachefly.net/50mb.test"
	req, err := http.NewRequestWithContext(cmdCtx, "GET", testURL, nil)
	if err != nil {
		return 0, 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("speed test request: %w", err)
	}
	defer resp.Body.Close()

	// Download started = config is healthy
	start := time.Now()
	var totalBytes int64
	buf := make([]byte, 32*1024)

	speedCtx, speedCancel := context.WithTimeout(cmdCtx, 10*time.Second)
	defer speedCancel()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			select {
			case <-speedCtx.Done():
				return
			default:
			}
			n, err := resp.Body.Read(buf)
			if n > 0 {
				totalBytes += int64(n)
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-readDone:
	case <-speedCtx.Done():
	}

	elapsed := time.Since(start).Seconds()
	speedKBps := float64(0)
	if elapsed > 0 {
		speedKBps = float64(totalBytes) / elapsed / 1024
	}

	return speedKBps, totalBytes, nil
}

// waitForPort checks if a port is accepting connections
func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
