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

func TestTlsOptions_Nil(t *testing.T) {
	opts := tlsOptions(nil)
	assert.Nil(t, opts)
}

func TestTlsOptions_CACertOnly(t *testing.T) {
	caCert, _, _, _ := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert: caCert,
	})

	// Should have exactly 1 option: nats.Secure(tc)
	assert.Len(t, opts, 1)
}

func TestTlsOptions_CACertWithTLSFirst(t *testing.T) {
	caCert, _, _, _ := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert:   caCert,
		TLSFirst: true,
	})

	// Should have 2 options: nats.Secure(tc) + nats.TLSHandshakeFirst()
	assert.Len(t, opts, 2)
}

func TestTlsOptions_CACertWithClientCert(t *testing.T) {
	caCert, _, clientCert, clientKey := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	})

	// Should have 1 option: nats.Secure(tc) with client cert embedded
	assert.Len(t, opts, 1)
}

func TestTlsOptions_TLSFirstOnly(t *testing.T) {
	opts := tlsOptions(&TLSConfig{
		TLSFirst: true,
	})

	// Should have 2 options: nats.Secure() (system CA) + nats.TLSHandshakeFirst()
	assert.Len(t, opts, 2)
}

func TestTlsOptions_NoCACert(t *testing.T) {
	opts := tlsOptions(&TLSConfig{})

	// Empty config with no CACert should still enable TLS with system CA pool
	assert.Len(t, opts, 1)
}

func TestTlsOptions_InvalidCACert(t *testing.T) {
	opts := tlsOptions(&TLSConfig{
		CACert: "not-a-valid-pem",
	})

	// Should still return an option (with empty pool), just logs a warning
	assert.Len(t, opts, 1)
}

func TestTlsOptions_InvalidClientCert(t *testing.T) {
	caCert, _, _, _ := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert:     caCert,
		ClientCert: "not-a-valid-cert",
		ClientKey:  "not-a-valid-key",
	})

	// Should still return the CA option, just logs an error for client cert
	assert.Len(t, opts, 1)
}

func TestTlsOptions_ApplyToNatsConn(t *testing.T) {
	// Verify that the generated options are valid nats.Option functions
	// by applying them to a nats.Options struct
	caCert, _, clientCert, clientKey := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		TLSFirst:   true,
	})

	natsOpts := &nats.Options{}
	for _, opt := range opts {
		err := opt(natsOpts)
		assert.NoError(t, err)
	}

	assert.True(t, natsOpts.TLSHandshakeFirst)
	assert.NotNil(t, natsOpts.TLSConfig)
	assert.NotNil(t, natsOpts.TLSConfig.RootCAs)
	assert.Len(t, natsOpts.TLSConfig.Certificates, 1)
}

func TestTlsOptions_CACertOnlyApply(t *testing.T) {
	caCert, _, _, _ := generateTestCert(t)

	opts := tlsOptions(&TLSConfig{
		CACert: caCert,
	})

	natsOpts := &nats.Options{}
	for _, opt := range opts {
		err := opt(natsOpts)
		assert.NoError(t, err)
	}

	assert.False(t, natsOpts.TLSHandshakeFirst)
	assert.NotNil(t, natsOpts.TLSConfig)
	assert.NotNil(t, natsOpts.TLSConfig.RootCAs)
	assert.Empty(t, natsOpts.TLSConfig.Certificates)
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

func TestCreateDefaultToolOptions_NilTLS(t *testing.T) {
	opts := createDefaultToolOptions("test", nil)
	// Should have: Name, Timeout, ReconnectWait, MaxReconnects,
	// DisconnectErrHandler, ReconnectHandler, ClosedHandler = 7 options
	assert.Len(t, opts, 7)
}

func TestCreateDefaultToolOptions_WithTLS(t *testing.T) {
	caCert, _, _, _ := generateTestCert(t)

	opts := createDefaultToolOptions("test", &TLSConfig{
		CACert:   caCert,
		TLSFirst: true,
	})
	// 7 base options + 2 TLS options (Secure + TLSHandshakeFirst) = 9
	assert.Len(t, opts, 9)
}
