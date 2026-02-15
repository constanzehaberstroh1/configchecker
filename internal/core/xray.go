package core

import (
	"encoding/json"
	"fmt"
)

type XrayCore struct{}

func init() {
	Register("xray", func() Core { return &XrayCore{} })
}

func (x *XrayCore) Name() string       { return "Xray" }
func (x *XrayCore) BinaryName() string { return "xray" }
func (x *XrayCore) IsAvailable() bool  { return IsAvailableInPath("xray") }

func (x *XrayCore) SupportedProtocols() []string {
	return []string{"vmess", "vless", "trojan", "ss", "shadowsocks"}
}

func (x *XrayCore) SupportsProtocol(proto string) bool {
	for _, p := range x.SupportedProtocols() {
		if p == proto {
			return true
		}
	}
	return false
}

func (x *XrayCore) RunArgs(configPath string) []string {
	return []string{"run", "-c", configPath}
}

func (x *XrayCore) GenerateConfig(pc ProxyConfig, socksPort int) ([]byte, error) {
	outbound, err := x.buildOutbound(pc)
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

func (x *XrayCore) buildOutbound(pc ProxyConfig) (map[string]interface{}, error) {
	switch pc.Protocol {
	case "vmess":
		return x.vmessOutbound(pc), nil
	case "vless":
		return x.vlessOutbound(pc), nil
	case "trojan":
		return x.trojanOutbound(pc), nil
	case "ss", "shadowsocks":
		return x.ssOutbound(pc), nil
	default:
		return nil, fmt.Errorf("xray: unsupported protocol %s", pc.Protocol)
	}
}

func (x *XrayCore) vmessOutbound(pc ProxyConfig) map[string]interface{} {
	stream := x.buildStreamSettings(pc)

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

func (x *XrayCore) vlessOutbound(pc ProxyConfig) map[string]interface{} {
	stream := x.buildStreamSettings(pc)

	user := map[string]interface{}{
		"id":         pc.UUID,
		"encryption": "none",
	}
	if pc.Flow != "" {
		user["flow"] = pc.Flow
	}

	return map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": pc.Address,
					"port":    pc.Port,
					"users":   []map[string]interface{}{user},
				},
			},
		},
		"streamSettings": stream,
	}
}

func (x *XrayCore) trojanOutbound(pc ProxyConfig) map[string]interface{} {
	stream := x.buildStreamSettings(pc)

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

func (x *XrayCore) ssOutbound(pc ProxyConfig) map[string]interface{} {
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

func (x *XrayCore) buildStreamSettings(pc ProxyConfig) map[string]interface{} {
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
	case "tcp":
		if pc.HeaderType == "http" {
			stream["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": "http",
					"request": map[string]interface{}{
						"path":    []string{pc.Path},
						"headers": map[string]interface{}{"Host": []string{pc.Host}},
					},
				},
			}
		}
	}

	switch pc.Security {
	case "tls":
		stream["security"] = "tls"
		tls := map[string]interface{}{"allowInsecure": true}
		if pc.SNI != "" {
			tls["serverName"] = pc.SNI
		}
		if pc.Fingerprint != "" {
			tls["fingerprint"] = pc.Fingerprint
		}
		if len(pc.ALPN) > 0 {
			tls["alpn"] = pc.ALPN
		}
		stream["tlsSettings"] = tls
	case "reality":
		stream["security"] = "reality"
		reality := map[string]interface{}{
			"show":        false,
			"fingerprint": pc.Fingerprint,
		}
		if pc.SNI != "" {
			reality["serverName"] = pc.SNI
		}
		if pc.PublicKey != "" {
			reality["publicKey"] = pc.PublicKey
		}
		if pc.ShortID != "" {
			reality["shortId"] = pc.ShortID
		}
		if pc.SpiderX != "" {
			reality["spiderX"] = pc.SpiderX
		}
		stream["realitySettings"] = reality
	}

	return stream
}
