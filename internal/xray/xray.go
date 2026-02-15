package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/configchecker/internal/logger"
)

// Manager handles xray-core process lifecycle
type Manager struct {
	xrayPath string
	log      *logger.Logger
	mu       sync.Mutex
}

// NewManager creates a new xray manager
func NewManager(log *logger.Logger) *Manager {
	return &Manager{
		xrayPath: findXrayBinary(),
		log:      log,
	}
}

// GetXrayPath returns the xray binary path
func (m *Manager) GetXrayPath() string {
	return m.xrayPath
}

// PingConfig tests if a v2ray config's server is reachable via xray core
// Returns latency in ms or error
func (m *Manager) PingConfig(ctx context.Context, configLine string, timeout time.Duration) (int64, error) {
	port, err := getFreePort()
	if err != nil {
		return 0, fmt.Errorf("getting free port: %w", err)
	}

	xrayConfig, err := generateXrayConfig(configLine, port)
	if err != nil {
		return 0, fmt.Errorf("generating xray config: %w", err)
	}

	tmpDir := os.TempDir()
	configFile := filepath.Join(tmpDir, fmt.Sprintf("xray_ping_%d.json", port))
	if err := os.WriteFile(configFile, xrayConfig, 0644); err != nil {
		return 0, fmt.Errorf("writing config: %w", err)
	}
	defer os.Remove(configFile)

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, m.xrayPath, "run", "-c", configFile)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting xray: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	if !waitForPort(port, 5*time.Second) {
		return 0, fmt.Errorf("xray proxy not ready on port %d", port)
	}

	start := time.Now()
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSHandshakeTimeout:   10 * time.Second,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	req, err := http.NewRequestWithContext(cmdCtx, "GET", "https://www.google.com/generate_204", nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connectivity test failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	latency := time.Since(start).Milliseconds()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return latency, nil
}

// SpeedTest downloads a test file via xray proxy and returns speed in KB/s
func (m *Manager) SpeedTest(ctx context.Context, configLine string, timeout time.Duration) (float64, int64, error) {
	port, err := getFreePort()
	if err != nil {
		return 0, 0, fmt.Errorf("getting free port: %w", err)
	}

	xrayConfig, err := generateXrayConfig(configLine, port)
	if err != nil {
		return 0, 0, fmt.Errorf("generating xray config: %w", err)
	}

	tmpDir := os.TempDir()
	configFile := filepath.Join(tmpDir, fmt.Sprintf("xray_speed_%d.json", port))
	if err := os.WriteFile(configFile, xrayConfig, 0644); err != nil {
		return 0, 0, fmt.Errorf("writing config: %w", err)
	}
	defer os.Remove(configFile)

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, m.xrayPath, "run", "-c", configFile)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("starting xray: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	if !waitForPort(port, 5*time.Second) {
		return 0, 0, fmt.Errorf("xray proxy not ready")
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSHandshakeTimeout:   10 * time.Second,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}

	testURL := "https://cachefly.cachefly.net/50mb.test"
	req, err := http.NewRequestWithContext(cmdCtx, "GET", testURL, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("speed test request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("speed test HTTP %d", resp.StatusCode)
	}

	// Download started successfully — even if speed is 0, config is healthy
	start := time.Now()
	var totalBytes int64
	buf := make([]byte, 32*1024)

	// Read for up to 10 seconds to measure speed
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
				n, readErr := resp.Body.Read(buf)
				totalBytes += int64(n)
				if readErr != nil {
					return
				}
			}
		}
	}()

	select {
	case <-readDone:
	case <-speedCtx.Done():
	}

	elapsed := time.Since(start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	speedKBps := float64(totalBytes) / 1024.0 / elapsed

	return speedKBps, totalBytes, nil
}

// generateXrayConfig creates a minimal xray JSON config
func generateXrayConfig(configLine string, socksPort int) ([]byte, error) {
	outbound, err := parseConfigToOutbound(configLine)
	if err != nil {
		return nil, err
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "none",
		},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"udp": true,
				},
			},
		},
		"outbounds": []interface{}{outbound},
	}

	return json.Marshal(config)
}

// parseConfigToOutbound converts a v2ray config URI into an xray outbound config
func parseConfigToOutbound(configLine string) (map[string]interface{}, error) {
	configLine = strings.TrimSpace(configLine)

	switch {
	case strings.HasPrefix(configLine, "vmess://"):
		return parseVmess(configLine)
	case strings.HasPrefix(configLine, "vless://"):
		return parseVless(configLine)
	case strings.HasPrefix(configLine, "trojan://"):
		return parseTrojan(configLine)
	case strings.HasPrefix(configLine, "ss://"):
		return parseShadowsocks(configLine)
	case strings.HasPrefix(configLine, "hysteria2://"), strings.HasPrefix(configLine, "hy2://"):
		return parseHysteria2(configLine)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", truncate(configLine, 20))
	}
}

func parseVmess(configLine string) (map[string]interface{}, error) {
	raw := strings.TrimPrefix(configLine, "vmess://")
	data, err := b64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding vmess: %w", err)
	}

	var vmess map[string]interface{}
	if err := json.Unmarshal(data, &vmess); err != nil {
		return nil, fmt.Errorf("parsing vmess JSON: %w", err)
	}

	addr := getStr(vmess, "add")
	port := getNum(vmess, "port")
	id := getStr(vmess, "id")
	netType := getStr(vmess, "net")
	tls := getStr(vmess, "tls")
	sni := getStr(vmess, "sni")
	host := getStr(vmess, "host")
	path := getStr(vmess, "path")
	aid := getNum(vmess, "aid")

	if addr == "" || port == 0 || id == "" {
		return nil, fmt.Errorf("incomplete vmess config")
	}

	if netType == "" {
		netType = "tcp"
	}

	streamSettings := map[string]interface{}{
		"network": netType,
	}

	switch netType {
	case "ws":
		ws := map[string]interface{}{"path": path}
		if host != "" {
			ws["headers"] = map[string]interface{}{"Host": host}
		}
		streamSettings["wsSettings"] = ws
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{"serviceName": path}
	case "tcp":
		if getStr(vmess, "type") == "http" {
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": "http",
					"request": map[string]interface{}{
						"path":    []string{path},
						"headers": map[string]interface{}{"Host": []string{host}},
					},
				},
			}
		}
	case "h2", "http":
		h2 := map[string]interface{}{"path": path}
		if host != "" {
			h2["host"] = []string{host}
		}
		streamSettings["httpSettings"] = h2
	}

	if tls == "tls" {
		streamSettings["security"] = "tls"
		tlsS := map[string]interface{}{"allowInsecure": true}
		if sni != "" {
			tlsS["serverName"] = sni
		} else if host != "" {
			tlsS["serverName"] = host
		}
		streamSettings["tlsSettings"] = tlsS
	}

	return map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": addr,
					"port":    int(port),
					"users": []map[string]interface{}{
						{"id": id, "alterId": int(aid), "security": "auto"},
					},
				},
			},
		},
		"streamSettings": streamSettings,
	}, nil
}

func parseVless(configLine string) (map[string]interface{}, error) {
	raw := strings.TrimPrefix(configLine, "vless://")
	parts := strings.SplitN(raw, "#", 2)
	mainPart := parts[0]

	userHost := strings.SplitN(mainPart, "?", 2)
	connPart := userHost[0]
	params := url.Values{}
	if len(userHost) > 1 {
		p, err := url.ParseQuery(userHost[1])
		if err == nil {
			params = p
		}
	}

	atIdx := strings.Index(connPart, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid vless format")
	}
	uuid := connPart[:atIdx]
	hostPort := connPart[atIdx+1:]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port: %w", err)
	}
	port := portToInt(portStr)
	if port == 0 {
		return nil, fmt.Errorf("invalid port")
	}

	netType := params.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	security := params.Get("security")
	sni := params.Get("sni")
	fp := params.Get("fp")
	pbk := params.Get("pbk")
	sid := params.Get("sid")
	path := params.Get("path")
	headerHost := params.Get("host")
	flow := params.Get("flow")
	serviceName := params.Get("serviceName")

	streamSettings := map[string]interface{}{"network": netType}

	switch netType {
	case "ws":
		ws := map[string]interface{}{"path": path}
		if headerHost != "" {
			ws["headers"] = map[string]interface{}{"Host": headerHost}
		}
		streamSettings["wsSettings"] = ws
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{"serviceName": serviceName}
	case "h2", "http":
		h2 := map[string]interface{}{"path": path}
		if headerHost != "" {
			h2["host"] = []string{headerHost}
		}
		streamSettings["httpSettings"] = h2
	}

	switch security {
	case "tls":
		streamSettings["security"] = "tls"
		tlsS := map[string]interface{}{"allowInsecure": true}
		if sni != "" {
			tlsS["serverName"] = sni
		}
		if fp != "" {
			tlsS["fingerprint"] = fp
		}
		streamSettings["tlsSettings"] = tlsS
	case "reality":
		streamSettings["security"] = "reality"
		rs := map[string]interface{}{"show": false}
		if sni != "" {
			rs["serverName"] = sni
		}
		if fp != "" {
			rs["fingerprint"] = fp
		}
		if pbk != "" {
			rs["publicKey"] = pbk
		}
		if sid != "" {
			rs["shortId"] = sid
		}
		streamSettings["realitySettings"] = rs
	}

	user := map[string]interface{}{"id": uuid, "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}

	return map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{"address": host, "port": port, "users": []map[string]interface{}{user}},
			},
		},
		"streamSettings": streamSettings,
	}, nil
}

func parseTrojan(configLine string) (map[string]interface{}, error) {
	raw := strings.TrimPrefix(configLine, "trojan://")
	parts := strings.SplitN(raw, "#", 2)
	mainPart := parts[0]

	userHost := strings.SplitN(mainPart, "?", 2)
	connPart := userHost[0]
	params := url.Values{}
	if len(userHost) > 1 {
		p, err := url.ParseQuery(userHost[1])
		if err == nil {
			params = p
		}
	}

	atIdx := strings.Index(connPart, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid trojan format")
	}
	password := connPart[:atIdx]
	hostPort := connPart[atIdx+1:]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port: %w", err)
	}
	port := portToInt(portStr)

	security := params.Get("security")
	sni := params.Get("sni")
	netType := params.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	path := params.Get("path")
	headerHost := params.Get("host")

	streamSettings := map[string]interface{}{"network": netType}

	switch netType {
	case "ws":
		ws := map[string]interface{}{"path": path}
		if headerHost != "" {
			ws["headers"] = map[string]interface{}{"Host": headerHost}
		}
		streamSettings["wsSettings"] = ws
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{"serviceName": params.Get("serviceName")}
	}

	if security == "" || security == "tls" {
		streamSettings["security"] = "tls"
		tlsS := map[string]interface{}{"allowInsecure": true}
		if sni != "" {
			tlsS["serverName"] = sni
		} else {
			tlsS["serverName"] = host
		}
		streamSettings["tlsSettings"] = tlsS
	}

	return map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": host, "port": port, "password": password},
			},
		},
		"streamSettings": streamSettings,
	}, nil
}

func parseShadowsocks(configLine string) (map[string]interface{}, error) {
	raw := strings.TrimPrefix(configLine, "ss://")
	parts := strings.SplitN(raw, "#", 2)
	mainPart := parts[0]

	atIdx := strings.LastIndex(mainPart, "@")
	var method, password, host string
	var port int

	if atIdx > 0 {
		userInfo := mainPart[:atIdx]
		hostPort := mainPart[atIdx+1:]

		if qIdx := strings.Index(hostPort, "?"); qIdx >= 0 {
			hostPort = hostPort[:qIdx]
		}

		decoded, err := b64Decode(userInfo)
		if err != nil {
			colonIdx := strings.Index(userInfo, ":")
			if colonIdx < 0 {
				return nil, fmt.Errorf("invalid ss format")
			}
			method = userInfo[:colonIdx]
			password = userInfo[colonIdx+1:]
		} else {
			decodedStr := string(decoded)
			colonIdx := strings.Index(decodedStr, ":")
			if colonIdx < 0 {
				return nil, fmt.Errorf("invalid decoded ss format")
			}
			method = decodedStr[:colonIdx]
			password = decodedStr[colonIdx+1:]
		}

		var portStr string
		var splitErr error
		host, portStr, splitErr = net.SplitHostPort(hostPort)
		if splitErr != nil {
			return nil, fmt.Errorf("parsing host:port: %w", splitErr)
		}
		port = portToInt(portStr)
	} else {
		decoded, err := b64Decode(mainPart)
		if err != nil {
			return nil, fmt.Errorf("decoding ss: %w", err)
		}
		decodedStr := string(decoded)
		colonIdx := strings.Index(decodedStr, ":")
		if colonIdx < 0 {
			return nil, fmt.Errorf("invalid decoded ss format")
		}
		method = decodedStr[:colonIdx]
		rest := decodedStr[colonIdx+1:]
		atIdx2 := strings.LastIndex(rest, "@")
		if atIdx2 < 0 {
			return nil, fmt.Errorf("invalid ss format")
		}
		password = rest[:atIdx2]
		hostPort := rest[atIdx2+1:]
		var portStr string
		var splitErr error
		host, portStr, splitErr = net.SplitHostPort(hostPort)
		if splitErr != nil {
			return nil, fmt.Errorf("parsing host:port: %w", splitErr)
		}
		port = portToInt(portStr)
	}

	return map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": host, "port": port, "method": method, "password": password},
			},
		},
	}, nil
}

func parseHysteria2(configLine string) (map[string]interface{}, error) {
	raw := configLine
	if strings.HasPrefix(raw, "hysteria2://") {
		raw = strings.TrimPrefix(raw, "hysteria2://")
	} else {
		raw = strings.TrimPrefix(raw, "hy2://")
	}

	parts := strings.SplitN(raw, "#", 2)
	mainPart := parts[0]

	userHost := strings.SplitN(mainPart, "?", 2)
	connPart := userHost[0]
	params := url.Values{}
	if len(userHost) > 1 {
		p, err := url.ParseQuery(userHost[1])
		if err == nil {
			params = p
		}
	}

	atIdx := strings.Index(connPart, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid hysteria2 format")
	}
	password := connPart[:atIdx]
	hostPort := connPart[atIdx+1:]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port: %w", err)
	}
	port := portToInt(portStr)

	sni := params.Get("sni")
	if sni == "" {
		sni = host
	}

	return map[string]interface{}{
		"protocol": "hysteria2",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": fmt.Sprintf("%s:%d", host, port), "password": password},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "hysteria2",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName": sni, "allowInsecure": true,
			},
		},
	}, nil
}

// Helper functions

func findXrayBinary() string {
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	paths := []string{"/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray", "./xray"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("xray.exe"); err == nil {
			return p
		}
	}
	return "xray"
}

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func getStr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func getNum(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case string:
		return float64(portToInt(n))
	default:
		return 0
	}
}

func portToInt(s string) int {
	var port int
	fmt.Sscanf(s, "%d", &port)
	return port
}

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")

	// Add appropriate padding
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
	if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return data, nil
	}

	return nil, fmt.Errorf("base64 decode failed")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
