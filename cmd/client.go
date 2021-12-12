package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/socks5"
	"github.com/tobyxdd/hysteria/pkg/transport"
)

func client(config *clientConfig) {
	logrus.WithField("config", config.String()).Info("Client configuration loaded")
	// TLS
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.Insecure,
		MinVersion:         tls.VersionTLS13,
	}
	if config.ALPN != "" {
		tlsConfig.NextProtos = []string{config.ALPN}
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
	}
	// Load CA
	if len(config.CustomCA) > 0 {
		bs, err := ioutil.ReadFile(config.CustomCA)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.CustomCA,
			}).Fatal("Failed to load CA")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			logrus.WithFields(logrus.Fields{
				"file": config.CustomCA,
			}).Fatal("Failed to parse CA")
		}
		tlsConfig.RootCAs = cp
	}
	// QUIC config
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindow,
		MaxConnectionReceiveWindow:     config.ReceiveWindow,
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if config.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if config.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	// Auth
	var auth []byte
	if len(config.Auth) > 0 {
		auth = config.Auth
	} else {
		auth = []byte(config.AuthString)
	}
	// Obfuscator
	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.NewXPlusObfuscator([]byte(config.Obfs))
	}
	// Client
	client, err := core.NewClient(config.Server, auth, tlsConfig, quicConfig, transport.DefaultTransport,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize client")
	}
	defer client.Close()
	logrus.WithField("addr", config.Server).Info("Connected")

	// Local
	errChan := make(chan error)
	if len(config.SOCKS5.Listen) > 0 {
		go func() {
			var authFunc func(user, password string) bool
			if config.SOCKS5.User != "" && config.SOCKS5.Password != "" {
				authFunc = func(user, password string) bool {
					return config.SOCKS5.User == user && config.SOCKS5.Password == password
				}
			}
			socks5server, err := socks5.NewServer(client, transport.DefaultTransport, config.SOCKS5.Listen, authFunc,
				time.Duration(config.SOCKS5.Timeout)*time.Second, nil, config.SOCKS5.DisableUDP,
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("SOCKS5 TCP request")
				},
				func(addr net.Addr, reqAddr string, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
							"dst":   reqAddr,
						}).Info("SOCKS5 TCP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr,
						}).Debug("SOCKS5 TCP EOF")
					}
				},
				func(addr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": addr.String(),
					}).Debug("SOCKS5 UDP associate")
				},
				func(addr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
						}).Info("SOCKS5 UDP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
						}).Debug("SOCKS5 UDP EOF")
					}
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize SOCKS5 server")
			}
			logrus.WithField("addr", config.SOCKS5.Listen).Info("SOCKS5 server up and running")
			errChan <- socks5server.ListenAndServe()
		}()
	}

	err = <-errChan
	logrus.WithField("error", err).Fatal("Client shutdown")
}
