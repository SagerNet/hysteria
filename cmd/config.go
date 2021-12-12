package main

import (
	"errors"
	"fmt"

	"github.com/yosuke-furukawa/json5/encoding/json5"
)

const (
	mbpsToBps = 125000

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
	DefaultMaxIncomingStreams      = 1024

	DefaultALPN = "hysteria"
)

type serverConfig struct {
	Listen string `json:"listen"`
	ACME   struct {
		Domains                 []string `json:"domains"`
		Email                   string   `json:"email"`
		DisableHTTPChallenge    bool     `json:"disable_http"`
		DisableTLSALPNChallenge bool     `json:"disable_tlsalpn"`
		AltHTTPPort             int      `json:"alt_http_port"`
		AltTLSALPNPort          int      `json:"alt_tlsalpn_port"`
	} `json:"acme"`
	CertFile string `json:"cert"`
	KeyFile  string `json:"key"`
	// Optional below
	UpMbps     int    `json:"up_mbps"`
	DownMbps   int    `json:"down_mbps"`
	DisableUDP bool   `json:"disable_udp"`
	ACL        string `json:"acl"`
	Obfs       string `json:"obfs"`
	Auth       struct {
		Mode   string           `json:"mode"`
		Config json5.RawMessage `json:"config"`
	} `json:"auth"`
	ALPN                string `json:"alpn"`
	PrometheusListen    string `json:"prometheus_listen"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn"`
	ReceiveWindowClient uint64 `json:"recv_window_client"`
	MaxConnClient       int    `json:"max_conn_client"`
	DisableMTUDiscovery bool   `json:"disable_mtu_discovery"`
	IPv6Only            bool   `json:"ipv6_only"`
}

func (c *serverConfig) Check() error {
	if len(c.Listen) == 0 {
		return errors.New("no listen address")
	}
	if len(c.ACME.Domains) == 0 && (len(c.CertFile) == 0 || len(c.KeyFile) == 0) {
		return errors.New("ACME domain or TLS cert not provided")
	}
	if c.UpMbps < 0 || c.DownMbps < 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindowClient != 0 && c.ReceiveWindowClient < 65536) {
		return errors.New("invalid receive window size")
	}
	if c.MaxConnClient < 0 {
		return errors.New("invalid max connections per client")
	}
	return nil
}

func (c *serverConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}

type Relay struct {
	Listen  string `json:"listen"`
	Remote  string `json:"remote"`
	Timeout int    `json:"timeout"`
}

func (r *Relay) Check() error {
	if len(r.Listen) == 0 {
		return errors.New("no relay listen address")
	}
	if len(r.Remote) == 0 {
		return errors.New("no relay remote address")
	}
	if r.Timeout != 0 && r.Timeout <= 4 {
		return errors.New("invalid relay timeout")
	}
	return nil
}

type clientConfig struct {
	Server   string `json:"server"`
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	// Optional below
	SOCKS5 struct {
		Listen     string `json:"listen"`
		Timeout    int    `json:"timeout"`
		DisableUDP bool   `json:"disable_udp"`
		User       string `json:"user"`
		Password   string `json:"password"`
	} `json:"socks5"`
	Obfs                string `json:"obfs"`
	Auth                []byte `json:"auth"`
	AuthString          string `json:"auth_str"`
	ALPN                string `json:"alpn"`
	ServerName          string `json:"server_name"`
	Insecure            bool   `json:"insecure"`
	CustomCA            string `json:"ca"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn"`
	ReceiveWindow       uint64 `json:"recv_window"`
	DisableMTUDiscovery bool   `json:"disable_mtu_discovery"`
}

func (c *clientConfig) Check() error {
	if len(c.SOCKS5.Listen) == 0 {
		return errors.New("please enable at least one mode")
	}
	if c.SOCKS5.Timeout != 0 && c.SOCKS5.Timeout <= 4 {
		return errors.New("invalid SOCKS5 timeout")
	}
	if len(c.Server) == 0 {
		return errors.New("no server address")
	}
	if c.UpMbps <= 0 || c.DownMbps <= 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindow != 0 && c.ReceiveWindow < 65536) {
		return errors.New("invalid receive window size")
	}
	return nil
}

func (c *clientConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}
