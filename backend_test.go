package natsbackend

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
)

const (
	envVarRunAccTests = "VAULT_ACC"
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*NatsBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*NatsBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

func TestCaseFoldedKeysCannotOverridePath(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	ctx := context.Background()
	do := func(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: reqStorage, Data: data})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		return resp
	}

	do(logical.CreateOperation, "issue/operator/op1", map[string]interface{}{"claims": map[string]interface{}{"operator": map[string]interface{}{"signingKeys": []string{"sk1", "sk2"}}}})
	do(logical.CreateOperation, "issue/operator/op1/account/acc1", nil)
	do(logical.CreateOperation, "issue/operator/op1/account/acc1/user/alice", nil)
	do(logical.CreateOperation, "issue/operator/op1/account/acc1/user/bob", nil)

	alice := do(logical.ReadOperation, "nkey/operator/op1/account/acc1/user/alice", nil)
	resp := do(logical.ReadOperation, "nkey/operator/op1/account/acc1/user/alice", map[string]interface{}{"uſer": "bob"})
	assert.Equal(t, alice.Data["seed"], resp.Data["seed"])

	sk1 := do(logical.ReadOperation, "nkey/operator/op1/signing/sk1", nil)
	resp = do(logical.ReadOperation, "nkey/operator/op1/signing/sk1", map[string]interface{}{"ſigning": "sk2"})
	assert.Equal(t, sk1.Data["seed"], resp.Data["seed"])

	do(logical.UpdateOperation, "issue/operator/op1/account/acc1/user/alice", map[string]interface{}{
		"uſer":   "bob",
		"claims": map[string]interface{}{"user": map[string]interface{}{"pub": map[string]interface{}{"allow": []string{">"}}}},
	})
	resp = do(logical.ReadOperation, "issue/operator/op1/account/acc1/user/bob", nil)
	assert.Empty(t, resp.Data["claims"].(map[string]interface{})["user"].(map[string]interface{})["pub"])
}

func TestConcurrentUserDeletesKeepAllRevocations(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	ctx := context.Background()
	do := func(op logical.Operation, path string) *logical.Response {
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: reqStorage})
		assert.NoError(t, err)
		assert.False(t, resp.IsError())
		return resp
	}

	do(logical.CreateOperation, "issue/operator/op1")
	do(logical.CreateOperation, "issue/operator/op1/account/acc1")
	const users = 20
	for i := range users {
		do(logical.CreateOperation, fmt.Sprintf("issue/operator/op1/account/acc1/user/u%d", i))
	}

	var wg sync.WaitGroup
	for i := range users {
		wg.Go(func() {
			do(logical.DeleteOperation, fmt.Sprintf("issue/operator/op1/account/acc1/user/u%d", i))
		})
	}
	wg.Wait()

	issue, err := readAccountIssue(ctx, reqStorage, IssueAccountParameters{Operator: "op1", Account: "acc1"})
	assert.NoError(t, err)
	assert.Len(t, issue.Status.Revocations, users)
}

func TestPeriodicContinuesAfterFailure(t *testing.T) {
	ctx := context.Background()
	b, s := getTestBackend(t)
	sync := map[string]interface{}{"syncAccountServer": true}
	for path, data := range map[string]map[string]interface{}{"issue/operator/op0": sync, "issue/operator/op1": sync} {
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: s, Data: data})
		assert.NoError(t, err)
		assert.False(t, resp != nil && resp.IsError(), "%v", resp)
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "issue/operator/op1/account/acc1", Storage: s})
	assert.NoError(t, err)
	assert.False(t, resp != nil && resp.IsError(), "%v", resp)
	assert.NoError(t, s.Put(ctx, &logical.StorageEntry{Key: getAccountIssuePath("op0", "broken"), Value: []byte("{")}))
	assert.NoError(t, deleteAccountJWT(ctx, s, JWTParameters{Operator: "op1", Account: "acc1"}))

	assert.Error(t, b.periodicFunc(ctx, &logical.Request{Storage: s}))

	jwt, err := readAccountJWT(ctx, s, JWTParameters{Operator: "op1", Account: "acc1"})
	assert.NoError(t, err)
	assert.NotNil(t, jwt)
}
