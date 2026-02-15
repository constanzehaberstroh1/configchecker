package core

import (
	"encoding/json"
	"fmt"
)

type SingBoxCore struct{}

func init() {
	Register("singbox", func() Core { return &SingBoxCore{} })
}

func (s *SingBoxCore) Name() string       { return "sing-box" }
func (s *SingBoxCore) BinaryName() string { return "sing-box" }
func (s *SingBoxCore) IsAvailable() bool  { return IsAvailableInPath("sing-box") }

func (s *SingBoxCore) SupportedProtocols() []string {
	return []string{"vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "tuic", "naive", "wireguard"}
}

func (s *SingBoxCore) SupportsProtocol(proto string) bool {
	for _, p := range s.SupportedProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

func (s *SingBoxCore) RunArgs(configPath string) []string {
	return []string{"run", "-c", configPath}
}

func (s *SingBoxCore) GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error) {
	outbound, err := s.buildOutbound(pc)
	if err != nil {
		return nil, err
	}

	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []interface{}{outbound},
	}

	return json.Marshal(config)
}

func (s *SingBoxCore) buildOutbound(pc ProxyConfig) (map[string]interface{}, error) {
	switch pc.Protocol {
	case "vmess":
		return s.vmessOutbound(pc), nil
	case "vless":
		return s.vlessOutbound(pc), nil
	case "trojan":
		return s.trojanOutbound(pc), nil
	case "ss", "shadowsocks":
		return s.ssOutbound(pc), nil
	case "hysteria2":
		return s.hy2Outbound(pc), nil
	case "tuic":
		return s.tuicOutbound(pc), nil
	case "naive":
		return s.naiveOutbound(pc), nil
	default:
		return nil, fmt.Errorf("sing-box: unsupported protocol %s", pc.Protocol)
	}
}

func (s *SingBoxCore) vmessOutbound(pc ProxyConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":        "vmess",
		"tag":         "proxy",
		"server":      pc.Address,
		"server_port": pc.Port,
		"uuid":        pc.UUID,
		"alter_id":    pc.AlterId,
		"security":    "auto",
	}

	s.applyTransport(out, pc)
	s.applyTLS(out, pc)
	return out
}

func (s *SingBoxCore) vlessOutbound(pc ProxyConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":        "vless",
		"tag":         "proxy",
		"server":      pc.Address,
		"server_port": pc.Port,
		"uuid":        pc.UUID,
	}

	if pc.Flow != "" {
		out["flow"] = pc.Flow
	}

	s.applyTransport(out, pc)
	s.applyTLS(out, pc)
	return out
}

func (s *SingBoxCore) trojanOutbound(pc ProxyConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":        "trojan",
		"tag":         "proxy",
		"server":      pc.Address,
		"server_port": pc.Port,
		"password":    pc.Password,
	}

	s.applyTransport(out, pc)
	s.applyTLS(out, pc)
	return out
}

func (s *SingBoxCore) ssOutbound(pc ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         "proxy",
		"server":      pc.Address,
		"server_port": pc.Port,
		"method":      pc.Method,
		"password":    pc.Password,
	}
}

func (s *SingBoxCore) hy2Outbound(pc ProxyConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "proxy",
		"server":      pc.Address,
		"server_port": pc.Port,
		"password":    pc.Password,
	}

	if pc.UpMbps > 0 {
		out["up_mbps"] = pc.UpMbps
	}
	if pc.DownMbps > 0 {
		out["down_mbps"] = pc.DownMbps
	}

	if pc.Obfs != "" {
		out["obfs"] = map[string]interface{}{
			"type":     pc.Obfs,
			"password": pc.ObfsPass,
		}
	}

	// Hysteria2 always needs TLS
	tls := map[string]interface{}{
		"enabled":  true,
		"insecure": true,
	}
	if pc.SNI != "" {
		tls["server_name"] = pc.SNI
	}
	if len(pc.ALPN) > 0 {
		tls["alpn"] = pc.ALPN
	}
	out["tls"] = tls

	return out
}

func (s *SingBoxCore) tuicOutbound(pc ProxyConfig) map[string]interface{} {
	out := map[string]interface{}{
		"type":               "tuic",
		"tag":                "proxy",
		"server":             pc.Address,
		"server_port":        pc.Port,
		"uuid":               pc.UUID,
		"password":           pc.Password,
		"congestion_control": pc.CongestionCtrl,
		"udp_relay_mode":     pc.UDPRelayMode,
	}

	tls := map[string]interface{}{
		"enabled":  true,
		"insecure": true,
	}
	if pc.SNI != "" {
		tls["server_name"] = pc.SNI
	}
	if len(pc.ALPN) > 0 {
		tls["alpn"] = pc.ALPN
	}
	out["tls"] = tls

	return out
}

func (s *SingBoxCore) naiveOutbound(pc ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":     "naive",
		"tag":      "proxy",
		"server":   fmt.Sprintf("https://%s:%d", pc.Address, pc.Port),
		"username": pc.UUID,
		"password": pc.Password,
	}
}

func (s *SingBoxCore) applyTransport(out map[string]interface{}, pc ProxyConfig) {
	switch pc.Network {
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
			"path": pc.Path,
		}
		if pc.Host != "" {
			transport["headers"] = map[string]interface{}{"Host": pc.Host}
		}
		out["transport"] = transport
	case "grpc":
		transport := map[string]interface{}{
			"type": "grpc",
		}
		if pc.ServiceName != "" {
			transport["service_name"] = pc.ServiceName
		}
		out["transport"] = transport
	case "h2", "http":
		transport := map[string]interface{}{
			"type": "http",
			"path": pc.Path,
		}
		if pc.Host != "" {
			transport["host"] = []string{pc.Host}
		}
		out["transport"] = transport
	}
}

func (s *SingBoxCore) applyTLS(out map[string]interface{}, pc ProxyConfig) {
	if !pc.TLS {
		return
	}

	tls := map[string]interface{}{
		"enabled":  true,
		"insecure": true,
	}

	if pc.SNI != "" {
		tls["server_name"] = pc.SNI
	}
	if len(pc.ALPN) > 0 {
		tls["alpn"] = pc.ALPN
	}

	if pc.Security == "reality" {
		tls["reality"] = map[string]interface{}{
			"enabled":    true,
			"public_key": pc.PublicKey,
			"short_id":   pc.ShortID,
		}
	}

	if pc.Fingerprint != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": pc.Fingerprint,
		}
	}

	out["tls"] = tls
}
