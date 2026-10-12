package natsbackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// natsBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type NatsBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *NatsClient
	locks  []*sync.Mutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *NatsBackend {
	var b = NatsBackend{
		locks: locksutil.CreateGenericLocks[sync.Mutex](),
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathNkey(&b),
			pathJWT(&b),
			pathIssue(&b),
			pathCreds(&b),
			[]*framework.Path{},
		),
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollbackMinAge: 30 * time.Second,
		PeriodicFunc:      b.periodicFunc,
	}

	return &b
}

// backendHelp should contain help information for the backend
const backendHelp = `
The HashiCups secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage HashiCups user tokens
must be configured with the "config/" endpoints.
`

// reset clears any client configuration for a new
// backend to be configured
func (b *NatsBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *NatsBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *NatsBackend) getClient(ctx context.Context, s logical.Storage) (*NatsClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock
	return b.client, nil
}

func (b *NatsBackend) put(ctx context.Context, s logical.Storage, path string, data interface{}) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	entry, err := logical.StorageEntryJSON(path, data)
	if err != nil {
		return fmt.Errorf("error creating storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error writing to backend: %w", err)
	}

	return nil
}

func getFromStorage[T any](ctx context.Context, s logical.Storage, path string) (*T, error) {
	if path == "" {
		return nil, fmt.Errorf("missing path")
	}

	// get data entry from storage backend
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Data: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// convert json data to T
	var t T
	if err := entry.DecodeJSON(&t); err != nil {
		return nil, fmt.Errorf("error decoding JWT data: %w", err)
	}
	return &t, nil
}

func deleteFromStorage(ctx context.Context, s logical.Storage, path string) error {
	if err := s.Delete(ctx, path); err != nil {
		return fmt.Errorf("error deleting data: %w", err)
	}
	return nil
}

func storeInStorage[T any](ctx context.Context, s logical.Storage, path string, t *T) error {
	entry, err := logical.StorageEntryJSON(path, t)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// get returns the field value or the zero value of T when the field is unset or not in the path schema.
func get[T any](data *framework.FieldData, key string) T {
	v, _ := data.GetOk(key)
	t, _ := v.(T)
	return t
}

func (b *NatsBackend) periodicFunc(ctx context.Context, sys *logical.Request) error {
	b.Logger().Info("Periodic: starting periodic func for syncing accounts to nats")
	operators, err := listOperatorIssues(ctx, sys.Storage)
	if err != nil {
		return err
	}
	var errs []error
	for _, operator := range operators {
		if err := b.periodicSyncOperator(ctx, sys.Storage, operator); err != nil {
			errs = append(errs, fmt.Errorf("operator %s: %w", operator, err))
		}
	}
	return errors.Join(errs...)
}

func (b *NatsBackend) periodicSyncOperator(ctx context.Context, storage logical.Storage, operator string) error {
	operatorIssue, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
		Operator: operator,
	})
	if err != nil || operatorIssue == nil {
		return err
	}
	b.Logger().Debug(fmt.Sprintf("Periodic: operator %s selected for auto sync to account server", operator))
	accountNames, err := listAccountIssues(ctx, storage, operator)
	if err != nil {
		return err
	}
	var errs []error
	for _, account := range accountNames {
		if err := b.periodicSyncAccount(ctx, storage, operatorIssue, account); err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", account, err))
		}
	}
	return errors.Join(errs...)
}

func (b *NatsBackend) periodicSyncAccount(ctx context.Context, storage logical.Storage, operatorIssue *IssueOperatorStorage, account string) error {
	operator := operatorIssue.Operator
	defer locksutil.LockWithUnlock(b.locks, operator)()

	var errs []error
	if err := b.periodicRefreshAccountIssue(ctx, storage, operator, account); err != nil {
		errs = append(errs, err)
	}
	if err := b.periodicRefreshUserIssues(ctx, storage, operator, account); err != nil {
		errs = append(errs, err)
	}

	if !operatorIssue.SyncAccountServer {
		b.Logger().Info(fmt.Sprintf("Periodic: operator %s not configured for auto syncing to account server. Skipping.", operator))
		return errors.Join(errs...)
	}

	accountIssue, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil || accountIssue == nil {
		return errors.Join(append(errs, err)...)
	}
	b.Logger().Debug(fmt.Sprintf("Periodic: account %s in operator %s syncing to acount server", account, operator))
	if err = refreshAccountResolver(ctx, storage, accountIssue, AccountResolverActionPush); err != nil {
		return errors.Join(append(errs, err)...)
	}
	_, err = storeAccountIssueUpdate(ctx, storage, accountIssue)
	return errors.Join(append(errs, err)...)
}

func (b *NatsBackend) periodicRefreshUserIssues(ctx context.Context, storage logical.Storage, operator string, account string) error {
	issuesList, err := listUserIssues(ctx, storage, IssueUserParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, issueName := range issuesList {
		if err := periodicRefreshUserIssue(ctx, storage, operator, account, issueName); err != nil {
			errs = append(errs, fmt.Errorf("user %s: %w", issueName, err))
		}
	}
	return errors.Join(errs...)
}

func periodicRefreshUserIssue(ctx context.Context, storage logical.Storage, operator string, account string, user string) error {
	issue, err := readUserIssue(ctx, storage, IssueUserParameters{
		Operator: operator,
		Account:  account,
		User:     user,
	})
	if err != nil || issue == nil {
		return err
	}

	nkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: operator,
		Account:  account,
		User:     user,
	})
	if err != nil {
		return err
	}
	if !issue.Status.User.Nkey || nkey == nil {
		return refreshUser(ctx, storage, issue)
	}
	return nil
}

func (b *NatsBackend) periodicRefreshAccountIssue(ctx context.Context, storage logical.Storage, operator string, account string) error {
	issue, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil || issue == nil {
		return err
	}

	jwt, err := readAccountJWT(ctx, storage, JWTParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil {
		return err
	}
	jwtMissing := !issue.Status.Account.JWT || jwt == nil

	nkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: operator,
		Account:  account,
	})
	if err != nil {
		return err
	}
	nkeyMissing := !issue.Status.Account.Nkey || nkey == nil

	if jwtMissing || nkeyMissing || anyExpiredRevocations(issue) {
		return refreshAccount(ctx, storage, issue)
	}
	return nil
}

const deprecatedUserBeforeAccount = "creating a user before its account is deprecated and will be rejected in a future release"

func deprecatedWrite() *logical.Response {
	resp := &logical.Response{}
	resp.AddWarning("writing and deleting nkey/ and jwt/ paths is deprecated, they will become read-only; keys and JWTs are managed through issue/ paths")
	return resp
}
