package core

import (
	"encoding/json"
	"fmt"
)

type ShoesCore struct{}

func init() {
	Register("shoes", func() Core { return &ShoesCore{} })
}

func (s *ShoesCore) Name() string       { return "Shoes" }
func (s *ShoesCore) BinaryName() string { return "shoes" }
func (s *ShoesCore) IsAvailable() bool  { return IsAvailableInPath("shoes") }

func (s *ShoesCore) SupportedProtocols() []string {
	return []string{"vmess", "vless", "trojan", "ss", "shadowsocks"}
}

func (s *ShoesCore) SupportsProtocol(proto string) bool {
	for _, p := range s.SupportedProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

func (s *ShoesCore) RunArgs(configPath string) []string {
	return []string{"-c", configPath}
}

// GenerateConfig creates a shoes-compatible JSON proxy config
func (s *ShoesCore) GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error) {
	proxy, err := s.buildProxy(pc, socksPort)
	if err != nil {
		return nil, err
	}
	return json.Marshal(proxy)
}

func (s *ShoesCore) buildProxy(pc ProxyConfig, socksPort int) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"listen": fmt.Sprintf("socks://127.0.0.1:%d", socksPort),
	}

	var target string
	switch pc.Protocol {
	case "vmess":
		target = fmt.Sprintf("vmess://%s@%s:%d", pc.UUID, pc.Address, pc.Port)
	case "vless":
		target = fmt.Sprintf("vless://%s@%s:%d", pc.UUID, pc.Address, pc.Port)
	case "trojan":
		target = fmt.Sprintf("trojan://%s@%s:%d", pc.Password, pc.Address, pc.Port)
	case "ss", "shadowsocks":
		target = fmt.Sprintf("ss://%s:%s@%s:%d", pc.Method, pc.Password, pc.Address, pc.Port)
	default:
		return nil, fmt.Errorf("shoes: unsupported protocol %s", pc.Protocol)
	}

	config["target"] = target

	if pc.TLS {
		config["tls"] = true
		if pc.SNI != "" {
			config["sni"] = pc.SNI
		}
	}

	return config, nil
}
