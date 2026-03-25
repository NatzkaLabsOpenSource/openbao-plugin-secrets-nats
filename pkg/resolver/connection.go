package resolver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

// TLSConfig holds TLS configuration for connecting to a TLS-enabled NATS server.
type TLSConfig struct {
	// CACert is a PEM-encoded CA certificate used to verify the server's certificate.
	CACert string
	// ClientCert is a PEM-encoded client certificate for mTLS (optional).
	ClientCert string
	// ClientKey is a PEM-encoded client private key for mTLS (optional).
	ClientKey string
	// TLSFirst enables TLS handshake before any NATS protocol exchange (handshake_first mode).
	TLSFirst bool
}

func (r *Resolver) CloseConnection() {
	if r != nil {
		if r.nc != nil {
			r.nc.Close()
		}
	}
}

func isNatsUrl(url string) bool {
	url = strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(url, "nats://") || strings.HasPrefix(url, ",nats://") ||
		strings.HasPrefix(url, "tls://") || strings.HasPrefix(url, ",tls://")
}

func createConnection(url string, userJWT []byte, userKp nkeys.KeyPair, tlsCfg *TLSConfig) (*nats.Conn, error) {
	if !isValidURL(url) {
		return nil, fmt.Errorf("invalid url: %s", url)
	}

	if !isNatsUrl(url) {
		return nil, fmt.Errorf("invalid url: %s, only nats:// and tls:// urls are supported", url)
	}

	nats.NewInbox()
	getOpt := func(theJWT string, kp nkeys.KeyPair) nats.Option {
		return nats.UserJWT(
			func() (string, error) {
				return theJWT, nil
			}, func(nonce []byte) ([]byte, error) {
				return kp.Sign(nonce)
			})
	}

	return nats.Connect(url, createDefaultToolOptions("nsc_push", tlsCfg, getOpt(string(userJWT), userKp))...)
}

func createDefaultToolOptions(name string, tlsCfg *TLSConfig, o ...nats.Option) []nats.Option {
	connectTimeout := 5 * time.Second
	totalWait := 10 * time.Minute
	reconnectDelay := 2 * time.Second

	opts := []nats.Option{nats.Name(name)}
	opts = append(opts, nats.Timeout(connectTimeout))
	opts = append(opts, tlsOptions(tlsCfg)...)
	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		if err != nil {
			log.Error().Msgf("Disconnected: error: %v\n", err)
		}
		if nc.Status() == nats.CLOSED {
			return
		}
		log.Info().Msgf("Disconnected: will attempt reconnects for %.0fm", totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		log.Info().Msgf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		if nc.Status() == nats.CLOSED {
			return
		}
		log.Info().Msgf("Exiting, no servers available, or connection closed")
	}))
	opts = append(opts, o...)
	return opts
}

// tlsOptions builds NATS TLS options from the provided TLSConfig.
func tlsOptions(cfg *TLSConfig) []nats.Option {
	if cfg == nil {
		return nil
	}

	var opts []nats.Option

	if cfg.CACert != "" {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			log.Warn().Msg("resolver: failed to parse CA certificate, TLS server verification may fail")
		}
		tc := &tls.Config{
			RootCAs: certPool,
		}
		if cfg.ClientCert != "" && cfg.ClientKey != "" {
			cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
			if err != nil {
				log.Error().Err(err).Msg("resolver: failed to parse client certificate keypair")
			} else {
				tc.Certificates = []tls.Certificate{cert}
			}
		}
		opts = append(opts, nats.Secure(tc))
	} else {
		// No CA cert provided — use default system CA pool with TLS enabled.
		opts = append(opts, nats.Secure())
	}

	if cfg.TLSFirst {
		opts = append(opts, nats.TLSHandshakeFirst())
	}

	return opts
}

func isValidURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	supported := []string{"http", "https", "nats", "tls"}

	ok := false
	for _, v := range supported {
		if scheme == v {
			ok = true
			break
		}
	}
	return ok
}
