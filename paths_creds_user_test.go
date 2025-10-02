package natsbackend

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

func TestCRUDUserCreds(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	path := "creds/operator/op1/account/ac1/user/u1"

	t.Run("Test CRUD for user without setup", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("Test CRUD for user with non-expiring credentials", func(t *testing.T) {
		// operator
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// user
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1/user/u1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read creds
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])

		creds := resp.Data["creds"].(string)
		assert.NotEmpty(t, creds)

		token, err := jwt.ParseDecoratedJWT([]byte(creds))
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		_, err = jwt.ParseDecoratedNKey([]byte(creds))
		assert.NoError(t, err)

		claims, err := jwt.DecodeUserClaims(token)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), claims.Expires)
	})

	t.Run("Test CRUD for user with expiring credentials", func(t *testing.T) {
		// operator
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// account
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1",
			Storage:   reqStorage,
			Data:      map[string]interface{}{},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// user
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "issue/operator/op1/account/ac1/user/u1",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"credsTTL": 600,
			},
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())

		// read creds
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   reqStorage,
		})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		assert.NotNil(t, resp.Data["creds"])

		creds := resp.Data["creds"].(string)
		assert.NotEmpty(t, creds)

		token, err := jwt.ParseDecoratedJWT([]byte(creds))
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		_, err = jwt.ParseDecoratedNKey([]byte(creds))
		assert.NoError(t, err)

		claims, err := jwt.DecodeUserClaims(token)
		assert.NoError(t, err)
		assert.Greater(t, claims.Expires, time.Now().Unix())
	})
}
