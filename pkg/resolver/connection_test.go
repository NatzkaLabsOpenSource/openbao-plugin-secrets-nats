package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNatsUrl(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"nats://localhost:4222", true},
		{"nats://host1:4222,nats://host2:4222", true},
		{"tls://localhost:4222", true},
		{"tls://host1:4222,tls://host2:4222", true},
		{"NATS://localhost:4222", true},
		{"TLS://localhost:4222", true},
		{"http://localhost:4222", false},
		{"https://localhost:4222", false},
		{"", false},
		{"foobar", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNatsUrl(tt.url))
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"nats://localhost:4222", true},
		{"tls://localhost:4222", true},
		{"http://localhost:8080", true},
		{"https://localhost:8080", true},
		{"ftp://localhost", false},
		{"", false},
		{"  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidURL(tt.url))
		})
	}
}

// generateTestCert creates a self-signed CA certificate and key for testing.
func generateTestCert(t *testing.T) (caCertPEM, caKeyPEM, clientCertPEM, clientKeyPEM string) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	require.NoError(t, err)
	caKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}))

	// Generate client key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER}))

	return
}

// applyTLS builds the TLS options and applies them, returning the resulting nats.Options.
func applyTLS(t *testing.T, cfg *TLSConfig) (*nats.Options, error) {
	t.Helper()
	opts, err := tlsOptions(cfg)
	if err != nil {
		return nil, err
	}
	natsOpts := &nats.Options{}
	for _, opt := range opts {
		require.NoError(t, opt(natsOpts))
	}
	return natsOpts, nil
}

func TestTlsOptions(t *testing.T) {
	caCert, _, clientCert, clientKey := generateTestCert(t)

	tests := []struct {
		name          string
		cfg           *TLSConfig
		secure        bool
		handshake     bool
		customRootCAs bool
		clientCerts   int
	}{
		{
			// nats.go still upgrades on tls:// or when the server requires TLS
			name: "nil config adds nothing",
			cfg:  nil,
		},
		{
			name: "empty config adds nothing",
			cfg:  &TLSConfig{},
		},
		{
			name:      "tls first alone uses system CA pool",
			cfg:       &TLSConfig{TLSFirst: true},
			secure:    true,
			handshake: true,
		},
		{
			name:          "ca cert only",
			cfg:           &TLSConfig{CACert: caCert},
			secure:        true,
			customRootCAs: true,
		},
		{
			name:        "client cert without ca cert",
			cfg:         &TLSConfig{ClientCert: clientCert, ClientKey: clientKey},
			secure:      true,
			clientCerts: 1,
		},
		{
			name:          "everything",
			cfg:           &TLSConfig{CACert: caCert, ClientCert: clientCert, ClientKey: clientKey, TLSFirst: true},
			secure:        true,
			handshake:     true,
			customRootCAs: true,
			clientCerts:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := applyTLS(t, tt.cfg)
			require.NoError(t, err)

			assert.Equal(t, tt.secure, o.Secure)
			assert.Equal(t, tt.handshake, o.TLSHandshakeFirst)

			var rootCAs bool
			var certs int
			if o.TLSConfig != nil {
				rootCAs = o.TLSConfig.RootCAs != nil
				certs = len(o.TLSConfig.Certificates)
			}
			assert.Equal(t, tt.customRootCAs, rootCAs)
			assert.Equal(t, tt.clientCerts, certs)
		})
	}
}

func TestTlsOptions_Errors(t *testing.T) {
	_, _, clientCert, clientKey := generateTestCert(t)

	tests := []struct {
		name string
		cfg  *TLSConfig
		want string
	}{
		{"invalid ca cert", &TLSConfig{CACert: "not-a-valid-pem"}, "tlsCaCert"},
		{"client cert without key", &TLSConfig{ClientCert: clientCert}, "must be set together"},
		{"client key without cert", &TLSConfig{ClientKey: clientKey}, "must be set together"},
		{"invalid keypair", &TLSConfig{ClientCert: "not-a-valid-cert", ClientKey: "not-a-valid-key"}, "cannot parse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tlsOptions(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestCreateConnection_InvalidURL(t *testing.T) {
	_, err := createConnection("ftp://invalid", nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid url")
}

func TestCreateConnection_NonNatsURL(t *testing.T) {
	_, err := createConnection("http://localhost:4222", nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only nats:// and tls://")
}

func TestCreateConnection_InvalidTLSFailsBeforeDialing(t *testing.T) {
	_, err := createConnection("nats://127.0.0.1:1", nil, nil, &TLSConfig{CACert: "not-a-valid-pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tls configuration")
}
