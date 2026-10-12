package natsbackend

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningKeyReferences(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) func(logical.Operation, string, map[string]interface{}) *logical.Response {
		b, s := getTestBackend(t)
		do := func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
			resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: s, Data: data})
			require.NoError(t, err)
			return resp
		}
		ok := func(resp *logical.Response) { require.False(t, resp != nil && resp.IsError(), "%v", resp) }
		ok(do(logical.UpdateOperation, "issue/operator/op1", map[string]interface{}{
			"claims": map[string]interface{}{"operator": map[string]interface{}{"signingKeys": []string{"opsk1"}}},
		}))
		ok(do(logical.UpdateOperation, "issue/operator/op1/account/acc1", map[string]interface{}{
			"useSigningKey": "opsk1",
			"claims":        map[string]interface{}{"account": map[string]interface{}{"signingKeys": []string{"ask1"}}},
		}))
		ok(do(logical.UpdateOperation, "issue/operator/op1/account/acc1/user/u1", map[string]interface{}{"useSigningKey": "ask1"}))
		return do
	}

	t.Run("removing an operator signing key in use fails", func(t *testing.T) {
		do := setup(t)
		assert.True(t, do(logical.UpdateOperation, "issue/operator/op1", nil).IsError())
		assert.False(t, do(logical.ReadOperation, "nkey/operator/op1/signing/opsk1", nil).IsError())
	})

	t.Run("removing an account signing key in use fails", func(t *testing.T) {
		do := setup(t)
		assert.True(t, do(logical.UpdateOperation, "issue/operator/op1/account/acc1", map[string]interface{}{"useSigningKey": "opsk1"}).IsError())
		assert.False(t, do(logical.ReadOperation, "nkey/operator/op1/account/acc1/signing/ask1", nil).IsError())
	})

	t.Run("deleting a signing nkey in use fails", func(t *testing.T) {
		do := setup(t)
		assert.True(t, do(logical.DeleteOperation, "nkey/operator/op1/signing/opsk1", nil).IsError())
		assert.True(t, do(logical.DeleteOperation, "nkey/operator/op1/account/acc1/signing/ask1", nil).IsError())
		assert.False(t, do(logical.ReadOperation, "nkey/operator/op1/signing/opsk1", nil).IsError())
		assert.False(t, do(logical.ReadOperation, "nkey/operator/op1/account/acc1/signing/ask1", nil).IsError())
	})

	t.Run("creating a user before its account warns", func(t *testing.T) {
		do := setup(t)
		assert.Nil(t, do(logical.UpdateOperation, "issue/operator/op1/account/acc1/user/u2", map[string]interface{}{"useSigningKey": "ask1"}))
		resp := do(logical.UpdateOperation, "issue/operator/op1/account/acc2/user/u1", map[string]interface{}{"useSigningKey": "ask1"})
		require.NotNil(t, resp)
		assert.False(t, resp.IsError())
		assert.Len(t, resp.Warnings, 1)
	})

	t.Run("unknown signing keys are rejected", func(t *testing.T) {
		do := setup(t)
		assert.True(t, do(logical.UpdateOperation, "issue/operator/op1/account/acc3", map[string]interface{}{"useSigningKey": "nope"}).IsError())
		assert.True(t, do(logical.ReadOperation, "issue/operator/op1/account/acc3", nil).IsError())
		assert.True(t, do(logical.UpdateOperation, "issue/operator/op1/account/acc1/user/u2", map[string]interface{}{"useSigningKey": "nope"}).IsError())
		assert.True(t, do(logical.ReadOperation, "issue/operator/op1/account/acc1/user/u2", nil).IsError())
	})
}
