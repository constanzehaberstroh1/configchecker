package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI parses any v2ray config URI into a universal ProxyConfig
func ParseURI(uri string) (ProxyConfig, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ProxyConfig{}, fmt.Errorf("empty URI")
	}

	pc := ProxyConfig{RawURI: uri}

	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return parseVmessURI(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseStandardURI(uri, "vless")
	case strings.HasPrefix(uri, "trojan://"):
		return parseStandardURI(uri, "trojan")
	case strings.HasPrefix(uri, "ss://"):
		return parseShadowsocksURI(uri)
	case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
		return parseStandardURI(uri, "hysteria2")
	case strings.HasPrefix(uri, "tuic://"):
		return parseTuicURI(uri)
	case strings.HasPrefix(uri, "snell://"):
		return parseStandardURI(uri, "snell")
	case strings.HasPrefix(uri, "naive+https://"), strings.HasPrefix(uri, "naive://"):
		return parseNaiveURI(uri)
	default:
		return pc, fmt.Errorf("unsupported protocol: %s", ProtocolFromURI(uri))
	}
}

// parseVmessURI decodes vmess:// base64 JSON
func parseVmessURI(uri string) (ProxyConfig, error) {
	raw := strings.TrimPrefix(uri, "vmess://")
	data, err := b64DecodeAny(raw)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("vmess base64 decode: %w", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return ProxyConfig{}, fmt.Errorf("vmess JSON parse: %w", err)
	}

	pc := ProxyConfig{
		Protocol: "vmess",
		RawURI:   uri,
		Address:  getStr(m, "add"),
		Port:     getInt(m, "port"),
		UUID:     getStr(m, "id"),
		AlterId:  getInt(m, "aid"),
		Network:  getStr(m, "net"),
		Remark:   getStr(m, "ps"),
	}

	if pc.Network == "" {
		pc.Network = "tcp"
	}

	// TLS
	tls := getStr(m, "tls")
	if tls == "tls" {
		pc.TLS = true
		pc.Security = "tls"
	}
	pc.SNI = getStr(m, "sni")
	pc.Host = getStr(m, "host")
	pc.Path = getStr(m, "path")
	pc.HeaderType = getStr(m, "type")
	pc.Fingerprint = getStr(m, "fp")
	pc.AllowInsecure = true

	if alpn := getStr(m, "alpn"); alpn != "" {
		pc.ALPN = strings.Split(alpn, ",")
	}

	return pc, nil
}

// parseStandardURI handles standard URI scheme: protocol://userinfo@host:port?params#remark
func parseStandardURI(uri string, protocol string) (ProxyConfig, error) {
	// Normalize hysteria2
	uri = strings.Replace(uri, "hy2://", "hysteria2://", 1)

	u, err := url.Parse(uri)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("parse URI: %w", err)
	}

	pc := ProxyConfig{
		Protocol: protocol,
		RawURI:   uri,
		Address:  u.Hostname(),
	}

	// Port
	if p := u.Port(); p != "" {
		pc.Port, _ = strconv.Atoi(p)
	}

	// User info
	if u.User != nil {
		pc.UUID = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			pc.Password = pwd
		} else {
			// For trojan/hy2, username IS the password
			if protocol == "trojan" || protocol == "hysteria2" || protocol == "snell" {
				pc.Password = pc.UUID
				pc.UUID = ""
			}
		}
	}

	// Remark
	if u.Fragment != "" {
		pc.Remark, _ = url.QueryUnescape(u.Fragment)
		if pc.Remark == "" {
			pc.Remark = u.Fragment
		}
	}

	// Query params
	params := u.Query()
	pc.Network = params.Get("type")
	if pc.Network == "" {
		pc.Network = "tcp"
	}

	security := params.Get("security")
	pc.SNI = params.Get("sni")
	pc.Fingerprint = params.Get("fp")
	pc.Path = params.Get("path")
	pc.Host = params.Get("host")
	pc.Flow = params.Get("flow")
	pc.ServiceName = params.Get("serviceName")
	pc.HeaderType = params.Get("headerType")
	pc.PublicKey = params.Get("pbk")
	pc.ShortID = params.Get("sid")
	pc.SpiderX = params.Get("spx")

	if alpn := params.Get("alpn"); alpn != "" {
		pc.ALPN = strings.Split(alpn, ",")
	}

	// Security
	switch security {
	case "tls":
		pc.TLS = true
		pc.Security = "tls"
	case "reality":
		pc.TLS = true
		pc.Security = "reality"
	case "none", "":
		pc.Security = "none"
		// Trojan and hysteria2 default to TLS
		if protocol == "trojan" || protocol == "hysteria2" {
			pc.TLS = true
			pc.Security = "tls"
		}
	default:
		pc.Security = security
	}

	if pc.SNI == "" && pc.TLS {
		pc.SNI = pc.Address
	}

	pc.AllowInsecure = params.Get("allowInsecure") == "1" || true

	// Hysteria2 specific
	if protocol == "hysteria2" {
		pc.Obfs = params.Get("obfs")
		pc.ObfsPass = params.Get("obfs-password")
		if up := params.Get("up"); up != "" {
			pc.UpMbps, _ = strconv.Atoi(up)
		}
		if down := params.Get("down"); down != "" {
			pc.DownMbps, _ = strconv.Atoi(down)
		}
	}

	// Snell specific
	if protocol == "snell" {
		if v := params.Get("version"); v != "" {
			pc.SnellVersion, _ = strconv.Atoi(v)
		}
		pc.ObfsMode = params.Get("obfs")
	}

	return pc, nil
}

// parseShadowsocksURI handles ss:// URIs (SIP002 and legacy format)
func parseShadowsocksURI(uri string) (ProxyConfig, error) {
	raw := strings.TrimPrefix(uri, "ss://")

	pc := ProxyConfig{
		Protocol: "ss",
		RawURI:   uri,
	}

	// Extract fragment (remark)
	if idx := strings.LastIndex(raw, "#"); idx >= 0 {
		pc.Remark, _ = url.QueryUnescape(raw[idx+1:])
		raw = raw[:idx]
	}

	// Extract query params
	var params url.Values
	if idx := strings.Index(raw, "?"); idx >= 0 {
		params, _ = url.ParseQuery(raw[idx+1:])
		raw = raw[:idx]
	}

	// Try SIP002 format: ss://base64(method:password)@host:port
	if atIdx := strings.LastIndex(raw, "@"); atIdx >= 0 {
		userInfo := raw[:atIdx]
		hostPort := raw[atIdx+1:]

		// Decode user info
		if decoded, err := b64DecodeAny(userInfo); err == nil {
			userInfo = string(decoded)
		}

		parts := strings.SplitN(userInfo, ":", 2)
		if len(parts) == 2 {
			pc.Method = parts[0]
			pc.Password = parts[1]
		}

		// Parse host:port
		host, port := splitHostPort(hostPort)
		pc.Address = host
		pc.Port, _ = strconv.Atoi(port)
	} else {
		// Legacy format: ss://base64(method:password@host:port)
		decoded, err := b64DecodeAny(raw)
		if err != nil {
			return pc, fmt.Errorf("ss decode: %w", err)
		}

		s := string(decoded)
		atIdx := strings.LastIndex(s, "@")
		if atIdx < 0 {
			return pc, fmt.Errorf("ss format invalid")
		}

		parts := strings.SplitN(s[:atIdx], ":", 2)
		if len(parts) == 2 {
			pc.Method = parts[0]
			pc.Password = parts[1]
		}

		host, port := splitHostPort(s[atIdx+1:])
		pc.Address = host
		pc.Port, _ = strconv.Atoi(port)
	}

	// Plugin from query params
	if params != nil {
		if plugin := params.Get("plugin"); plugin != "" {
			// Handle plugin like obfs-local, v2ray-plugin
			pc.Network = plugin
		}
	}

	return pc, nil
}

// parseTuicURI handles tuic:// URIs
func parseTuicURI(uri string) (ProxyConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("parse tuic URI: %w", err)
	}

	pc := ProxyConfig{
		Protocol: "tuic",
		RawURI:   uri,
		Address:  u.Hostname(),
		TLS:      true,
		Security: "tls",
	}

	if p := u.Port(); p != "" {
		pc.Port, _ = strconv.Atoi(p)
	}

	if u.User != nil {
		pc.UUID = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			pc.Password = pwd
		}
	}

	if u.Fragment != "" {
		pc.Remark, _ = url.QueryUnescape(u.Fragment)
	}

	params := u.Query()
	pc.SNI = params.Get("sni")
	if pc.SNI == "" {
		pc.SNI = pc.Address
	}
	pc.CongestionCtrl = params.Get("congestion_control")
	if pc.CongestionCtrl == "" {
		pc.CongestionCtrl = "bbr"
	}
	pc.UDPRelayMode = params.Get("udp_relay_mode")
	if pc.UDPRelayMode == "" {
		pc.UDPRelayMode = "native"
	}

	if alpn := params.Get("alpn"); alpn != "" {
		pc.ALPN = strings.Split(alpn, ",")
	}

	pc.AllowInsecure = true

	return pc, nil
}

// parseNaiveURI handles naive:// and naive+https:// URIs
func parseNaiveURI(uri string) (ProxyConfig, error) {
	// Normalize
	uri = strings.Replace(uri, "naive+https://", "https://", 1)
	uri = strings.Replace(uri, "naive://", "https://", 1)

	u, err := url.Parse(uri)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("parse naive URI: %w", err)
	}

	pc := ProxyConfig{
		Protocol: "naive",
		RawURI:   uri,
		Address:  u.Hostname(),
		TLS:      true,
		Security: "tls",
	}

	if p := u.Port(); p != "" {
		pc.Port, _ = strconv.Atoi(p)
	} else {
		pc.Port = 443
	}

	if u.User != nil {
		pc.UUID = u.User.Username() // naive uses username
		if pwd, ok := u.User.Password(); ok {
			pc.Password = pwd
		}
	}

	pc.SNI = pc.Address
	if u.Fragment != "" {
		pc.Remark = u.Fragment
	}

	return pc, nil
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func b64DecodeAny(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")

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
	return base64.RawURLEncoding.DecodeString(s)
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return strconv.FormatFloat(val, 'f', -1, 64)
		case json.Number:
			return val.String()
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case string:
			n, _ := strconv.Atoi(val)
			return n
		case json.Number:
			n, _ := val.Int64()
			return int(n)
		}
	}
	return 0
}

func splitHostPort(s string) (string, string) {
	// Handle IPv6: [::1]:port
	if strings.HasPrefix(s, "[") {
		if idx := strings.LastIndex(s, "]:"); idx >= 0 {
			return s[1:idx], s[idx+2:]
		}
		return strings.Trim(s, "[]"), ""
	}
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}
