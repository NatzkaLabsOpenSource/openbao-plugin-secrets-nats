package resolver

import (
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type Resolver struct {
	nc *nats.Conn
}

func NewResolver(url string, userJWT []byte, userKp nkeys.KeyPair, tlsCfg *TLSConfig) (*Resolver, error) {
	nc, err := createConnection(url, userJWT, userKp, tlsCfg)
	if err != nil {
		return nil, err
	}

	return &Resolver{
		nc: nc,
	}, nil
}
