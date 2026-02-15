package core

import (
	"encoding/json"
	"fmt"
)

type MihomoCore struct{}

func init() {
	Register("mihomo", func() Core { return &MihomoCore{} })
}

func (m *MihomoCore) Name() string       { return "Mihomo" }
func (m *MihomoCore) BinaryName() string { return "mihomo" }
func (m *MihomoCore) IsAvailable() bool  { return IsAvailableInPath("mihomo") }

func (m *MihomoCore) SupportedProtocols() []string {
	return []string{"vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "tuic", "snell", "wireguard"}
}

func (m *MihomoCore) SupportsProtocol(proto string) bool {
	for _, p := range m.SupportedProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

func (m *MihomoCore) RunArgs(configPath string) []string {
	return []string{"-f", configPath}
}

// GenerateConfig creates mihomo/clash YAML config as JSON
// Mihomo accepts JSON config files (undocumented but works)
func (m *MihomoCore) GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error) {
	proxy, err := m.buildProxy(pc)
	if err != nil {
		return nil, err
	}

	config := map[string]interface{}{
		"mixed-port":          socksPort,
		"bind-address":        "127.0.0.1",
		"mode":                "global",
		"log-level":           "silent",
		"allow-lan":           false,
		"external-controller": "",
		"proxies":             []interface{}{proxy},
		"proxy-groups": []map[string]interface{}{
			{
				"name":    "GLOBAL",
				"type":    "select",
				"proxies": []string{"test-proxy"},
			},
		},
	}

	return json.Marshal(config)
}

func (m *MihomoCore) buildProxy(pc ProxyConfig) (map[string]interface{}, error) {
	switch pc.Protocol {
	case "vmess":
		return m.vmessProxy(pc), nil
	case "vless":
		return m.vlessProxy(pc), nil
	case "trojan":
		return m.trojanProxy(pc), nil
	case "ss", "shadowsocks":
		return m.ssProxy(pc), nil
	case "hysteria2":
		return m.hy2Proxy(pc), nil
	case "tuic":
		return m.tuicProxy(pc), nil
	case "snell":
		return m.snellProxy(pc), nil
	default:
		return nil, fmt.Errorf("mihomo: unsupported protocol %s", pc.Protocol)
	}
}

func (m *MihomoCore) vmessProxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":    "test-proxy",
		"type":    "vmess",
		"server":  pc.Address,
		"port":    pc.Port,
		"uuid":    pc.UUID,
		"alterId": pc.AlterId,
		"cipher":  "auto",
		"udp":     true,
	}

	m.applyNetwork(p, pc)
	m.applyTLS(p, pc)
	return p
}

func (m *MihomoCore) vlessProxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":   "test-proxy",
		"type":   "vless",
		"server": pc.Address,
		"port":   pc.Port,
		"uuid":   pc.UUID,
		"udp":    true,
	}

	if pc.Flow != "" {
		p["flow"] = pc.Flow
	}

	m.applyNetwork(p, pc)
	m.applyTLS(p, pc)
	return p
}

func (m *MihomoCore) trojanProxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":     "test-proxy",
		"type":     "trojan",
		"server":   pc.Address,
		"port":     pc.Port,
		"password": pc.Password,
		"udp":      true,
	}

	m.applyNetwork(p, pc)
	m.applyTLS(p, pc)
	return p
}

func (m *MihomoCore) ssProxy(pc ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"name":     "test-proxy",
		"type":     "ss",
		"server":   pc.Address,
		"port":     pc.Port,
		"cipher":   pc.Method,
		"password": pc.Password,
		"udp":      true,
	}
}

func (m *MihomoCore) hy2Proxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":             "test-proxy",
		"type":             "hysteria2",
		"server":           pc.Address,
		"port":             pc.Port,
		"password":         pc.Password,
		"skip-cert-verify": true,
	}

	if pc.SNI != "" {
		p["sni"] = pc.SNI
	}
	if pc.UpMbps > 0 {
		p["up"] = fmt.Sprintf("%d Mbps", pc.UpMbps)
	}
	if pc.DownMbps > 0 {
		p["down"] = fmt.Sprintf("%d Mbps", pc.DownMbps)
	}
	if pc.Obfs != "" {
		p["obfs"] = pc.Obfs
		p["obfs-password"] = pc.ObfsPass
	}
	if len(pc.ALPN) > 0 {
		p["alpn"] = pc.ALPN
	}
	return p
}

func (m *MihomoCore) tuicProxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":                  "test-proxy",
		"type":                  "tuic",
		"server":                pc.Address,
		"port":                  pc.Port,
		"uuid":                  pc.UUID,
		"password":              pc.Password,
		"congestion-controller": pc.CongestionCtrl,
		"udp-relay-mode":        pc.UDPRelayMode,
		"skip-cert-verify":      true,
	}

	if pc.SNI != "" {
		p["sni"] = pc.SNI
	}
	if len(pc.ALPN) > 0 {
		p["alpn"] = pc.ALPN
	}
	return p
}

func (m *MihomoCore) snellProxy(pc ProxyConfig) map[string]interface{} {
	p := map[string]interface{}{
		"name":   "test-proxy",
		"type":   "snell",
		"server": pc.Address,
		"port":   pc.Port,
		"psk":    pc.Password,
		"udp":    true,
	}

	if pc.SnellVersion > 0 {
		p["version"] = pc.SnellVersion
	}
	if pc.ObfsMode != "" {
		p["obfs-opts"] = map[string]interface{}{
			"mode": pc.ObfsMode,
			"host": pc.Host,
		}
	}
	return p
}

func (m *MihomoCore) applyNetwork(p map[string]interface{}, pc ProxyConfig) {
	p["network"] = pc.Network

	switch pc.Network {
	case "ws":
		wsOpts := map[string]interface{}{"path": pc.Path}
		if pc.Host != "" {
			wsOpts["headers"] = map[string]interface{}{"Host": pc.Host}
		}
		p["ws-opts"] = wsOpts
	case "grpc":
		grpcOpts := map[string]interface{}{}
		if pc.ServiceName != "" {
			grpcOpts["grpc-service-name"] = pc.ServiceName
		}
		p["grpc-opts"] = grpcOpts
	case "h2", "http":
		h2Opts := map[string]interface{}{"path": pc.Path}
		if pc.Host != "" {
			h2Opts["host"] = []string{pc.Host}
		}
		p["h2-opts"] = h2Opts
	}
}

func (m *MihomoCore) applyTLS(p map[string]interface{}, pc ProxyConfig) {
	if pc.TLS {
		p["tls"] = true
		p["skip-cert-verify"] = true
	}

	if pc.SNI != "" {
		p["servername"] = pc.SNI
	}
	if len(pc.ALPN) > 0 {
		p["alpn"] = pc.ALPN
	}
	if pc.Fingerprint != "" {
		p["client-fingerprint"] = pc.Fingerprint
	}

	if pc.Security == "reality" {
		p["reality-opts"] = map[string]interface{}{
			"public-key": pc.PublicKey,
			"short-id":   pc.ShortID,
		}
	}
}
