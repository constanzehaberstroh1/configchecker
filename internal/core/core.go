package core

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// ProxyConfig is the universal parsed representation of any proxy config URI
type ProxyConfig struct {
	Protocol      string // vmess, vless, trojan, ss, hysteria2, tuic, snell, naive
	Address       string
	Port          int
	UUID          string // vmess/vless user id
	Password      string // trojan/ss/hy2/tuic/snell password
	Method        string // shadowsocks encryption method
	Network       string // tcp, ws, grpc, h2, http, quic, kcp
	Security      string // none, tls, reality
	TLS           bool
	SNI           string
	Host          string // ws/h2 host header
	Path          string // ws/h2/grpc path
	Flow          string // vless xtls-rprx-vision etc
	ALPN          []string
	Fingerprint   string // utls fingerprint
	PublicKey     string // reality public key
	ShortID       string // reality short id
	SpiderX       string // reality spiderX
	AlterId       int    // vmess alter id
	ServiceName   string // grpc service name
	HeaderType    string // tcp header type (http)
	Remark        string
	AllowInsecure bool

	// Hysteria2 specific
	Obfs     string // obfs type
	ObfsPass string // obfs password
	UpMbps   int    // upload speed limit
	DownMbps int    // download speed limit

	// TUIC specific
	CongestionCtrl string // congestion control algorithm
	UDPRelayMode   string // quic, native

	// Snell specific
	SnellVersion int
	ObfsMode     string // tls, http

	// Raw URI for fallback
	RawURI string
}

// Core is the interface each proxy core must implement
type Core interface {
	// Name returns the human-readable core name
	Name() string

	// BinaryName returns the expected binary name in PATH
	BinaryName() string

	// IsAvailable checks if the binary exists in PATH
	IsAvailable() bool

	// SupportedProtocols returns protocols this core can handle
	SupportedProtocols() []string

	// SupportsProtocol checks if a specific protocol is supported
	SupportsProtocol(protocol string) bool

	// GenerateConfig creates the core-specific config file content
	// that starts a SOCKS5 proxy on the given port for the given proxy config
	GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error)

	// RunArgs returns the command-line arguments to start the core with the config
	RunArgs(configPath string) []string
}

// Tester wraps a Core with ping and speed test capabilities
type Tester interface {
	PingConfig(ctx context.Context, configLine string, timeout time.Duration) (int64, error)
	SpeedTest(ctx context.Context, configLine string, timeout time.Duration) (float64, int64, error)
	GetCoreName() string
	GetBinaryPath() string
}

// CoreInfo describes a registered core
type CoreInfo struct {
	Name      string   `json:"name"`
	Binary    string   `json:"binary"`
	Available bool     `json:"available"`
	Protocols []string `json:"protocols"`
}

// Registry holds all available cores
var registry = map[string]func() Core{}

// Register adds a core factory to the registry
func Register(name string, factory func() Core) {
	registry[strings.ToLower(name)] = factory
}

// GetCore returns a core by name
func GetCore(name string) (Core, error) {
	factory, ok := registry[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown core: %s (available: %s)", name, ListCoreNames())
	}
	return factory(), nil
}

// ListCores returns info about all registered cores
func ListCores() []CoreInfo {
	var cores []CoreInfo
	for name, factory := range registry {
		c := factory()
		cores = append(cores, CoreInfo{
			Name:      name,
			Binary:    c.BinaryName(),
			Available: c.IsAvailable(),
			Protocols: c.SupportedProtocols(),
		})
	}
	return cores
}

// ListCoreNames returns available core names
func ListCoreNames() string {
	var names []string
	for name := range registry {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// BestCoreForProtocol finds the best available core for a protocol
func BestCoreForProtocol(protocol string) (Core, bool) {
	// Priority: sing-box > mihomo > xray > v2ray
	priority := []string{"singbox", "mihomo", "xray", "v2ray"}
	for _, name := range priority {
		if factory, ok := registry[name]; ok {
			c := factory()
			if c.IsAvailable() && c.SupportsProtocol(protocol) {
				return c, true
			}
		}
	}
	return nil, false
}

// IsAvailableInPath checks if binary exists in PATH
func IsAvailableInPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ProtocolFromURI extracts the protocol from a config URI
func ProtocolFromURI(uri string) string {
	// Handle standard scheme://
	if idx := strings.Index(uri, "://"); idx > 0 {
		proto := strings.ToLower(uri[:idx])
		switch proto {
		case "hy2":
			return "hysteria2"
		case "ssr":
			return "shadowsocksr"
		case "wg":
			return "wireguard"
		default:
			return proto
		}
	}
	return ""
}

// ParseRemarkFromURI extracts the remark/name from a URI fragment
func ParseRemarkFromURI(uri string) string {
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		remark, err := url.QueryUnescape(uri[idx+1:])
		if err != nil {
			return uri[idx+1:]
		}
		return remark
	}
	return ""
}
