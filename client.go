package natsbackend

import (
	nats "github.com/nats-io/nats.go"
)

// natsClient creates an object storing
// the client.
type NatsClient struct {
	*nats.Conn
}
