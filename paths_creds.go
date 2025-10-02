package natsbackend

import (
	"github.com/NatzkaLabsOpenSource/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// CredsParameters represents the parameters for a Creds operation
type CredsParameters struct {
	Operator string `json:"operator,omitempty"`
	Account  string `json:"account,omitempty"`
	User     string `json:"user,omitempty"`
}

// CredsData represents the the data returned by a Creds operation
type CredsData struct {
	Creds string `json:"creds"`
}

func pathCreds(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathUserCreds(b)...)
	return paths
}

func createResponseCredsData(creds *IssuedCreds) (*logical.Response, error) {
	d := &CredsData{
		Creds: creds.creds,
	}

	rval := map[string]interface{}{}
	err := stm.StructToMap(d, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}
