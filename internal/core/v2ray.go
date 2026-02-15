package core

import (
	"encoding/json"
	"fmt"
)

type V2RayCore struct{}

func init() {
	Register("v2ray", func() Core { return &V2RayCore{} })
}

func (v *V2RayCore) Name() string       { return "V2Ray" }
func (v *V2RayCore) BinaryName() string { return "v2ray" }
func (v *V2RayCore) IsAvailable() bool  { return IsAvailableInPath("v2ray") }

func (v *V2RayCore) SupportedProtocols() []string {
	return []string{"vmess", "vless", "trojan", "ss", "shadowsocks"}
}

func (v *V2RayCore) SupportsProtocol(proto string) bool {
	for _, p := range v.SupportedProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

func (v *V2RayCore) RunArgs(configPath string) []string {
	return []string{"run", "-c", configPath}
}

// GenerateConfig creates v2ray-core JSON config (similar to xray but no Reality)
func (v *V2RayCore) GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error) {
	outbound, err := v.buildOutbound(pc)
	if err != nil {
		return nil, err
	}

	config := map[string]interface{}{
		"inbounds": []map[string]interface{}{
			{
				"tag":      "socks-in",
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{"udp": true},
			},
		},
		"outbounds": []interface{}{outbound},
	}

	return json.Marshal(config)
}

func (v *V2RayCore) buildOutbound(pc ProxyConfig) (map[string]interface{}, error) {
	// v2ray-core doesn't support Reality, reject those configs
	if pc.Security == "reality" {
		return nil, fmt.Errorf("v2ray-core does not support Reality")
	}

	switch pc.Protocol {
	case "vmess":
		return v.vmessOutbound(pc), nil
	case "vless":
		return v.vlessOutbound(pc), nil
	case "trojan":
		return v.trojanOutbound(pc), nil
	case "ss", "shadowsocks":
		return v.ssOutbound(pc), nil
	default:
		return nil, fmt.Errorf("v2ray: unsupported protocol %s", pc.Protocol)
	}
}

func (v *V2RayCore) vmessOutbound(pc ProxyConfig) map[string]interface{} {
	stream := v.buildStream(pc)

	return map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": pc.Address,
					"port":    pc.Port,
					"users": []map[string]interface{}{
						{"id": pc.UUID, "alterId": pc.AlterId, "security": "auto"},
					},
				},
			},
		},
		"streamSettings": stream,
	}
}

func (v *V2RayCore) vlessOutbound(pc ProxyConfig) map[string]interface{} {
	stream := v.buildStream(pc)

	return map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": pc.Address,
					"port":    pc.Port,
					"users": []map[string]interface{}{
						{"id": pc.UUID, "encryption": "none"},
					},
				},
			},
		},
		"streamSettings": stream,
	}
}

func (v *V2RayCore) trojanOutbound(pc ProxyConfig) map[string]interface{} {
	stream := v.buildStream(pc)

	return map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": pc.Address, "port": pc.Port, "password": pc.Password},
			},
		},
		"streamSettings": stream,
	}
}

func (v *V2RayCore) ssOutbound(pc ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  pc.Address,
					"port":     pc.Port,
					"method":   pc.Method,
					"password": pc.Password,
				},
			},
		},
	}
}

func (v *V2RayCore) buildStream(pc ProxyConfig) map[string]interface{} {
	stream := map[string]interface{}{"network": pc.Network}

	switch pc.Network {
	case "ws":
		ws := map[string]interface{}{"path": pc.Path}
		if pc.Host != "" {
			ws["headers"] = map[string]interface{}{"Host": pc.Host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]interface{}{}
		if pc.ServiceName != "" {
			grpc["serviceName"] = pc.ServiceName
		}
		stream["grpcSettings"] = grpc
	case "h2", "http":
		h2 := map[string]interface{}{"path": pc.Path}
		if pc.Host != "" {
			h2["host"] = []string{pc.Host}
		}
		stream["httpSettings"] = h2
		stream["network"] = "h2"
	}

	if pc.TLS {
		stream["security"] = "tls"
		tls := map[string]interface{}{"allowInsecure": true}
		if pc.SNI != "" {
			tls["serverName"] = pc.SNI
		}
		if len(pc.ALPN) > 0 {
			tls["alpn"] = pc.ALPN
		}
		stream["tlsSettings"] = tls
	}

	return stream
}
