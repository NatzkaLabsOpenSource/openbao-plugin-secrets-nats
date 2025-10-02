package natsbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/rs/zerolog/log"

	"github.com/NatzkaLabsOpenSource/openbao-plugin-secrets-nats/pkg/claims/user/v1alpha1"
	"github.com/NatzkaLabsOpenSource/openbao-plugin-secrets-nats/pkg/stm"
)

type IssueUserStorage struct {
	Operator      string              `json:"operator"`
	Account       string              `json:"account"`
	User          string              `json:"user"`
	UseSigningKey string              `json:"useSigningKey"`
	Claims        v1alpha1.UserClaims `json:"claims"`
	CredsTTL      int64               `json:"credsTTL,omitempty"`
	Status        IssueUserStatus     `json:"status"`
}

// IssueUserParameters is the user facing interface for configuring a user issue.
// Using pascal case on purpose.
// +k8s:deepcopy-gen=true
type IssueUserParameters struct {
	Operator      string              `json:"operator"`
	Account       string              `json:"account"`
	User          string              `json:"user"`
	UseSigningKey string              `json:"useSigningKey,omitempty"`
	Claims        v1alpha1.UserClaims `json:"claims,omitempty"`
	CredsTTL      int64               `json:"credsTTL,omitempty"`
}

type IssueUserData struct {
	Operator      string              `json:"operator"`
	Account       string              `json:"account"`
	User          string              `json:"user"`
	UseSigningKey string              `json:"useSigningKey"`
	Claims        v1alpha1.UserClaims `json:"claims"`
	CredsTTL      int64               `json:"credsTTL,omitempty"`
	Status        IssueUserStatus     `json:"status"`
}

type IssueUserStatus struct {
	User IssueStatus `json:"user"`
}

type IssuedCreds struct {
	jwt   string
	creds string
}

func pathUserIssue(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
				"user": {
					Type:        framework.TypeString,
					Description: "user identifier",
					Required:    false,
				},
				"useSigningKey": {
					Type:        framework.TypeString,
					Description: "signing key identifier",
					Required:    false,
				},
				"claims": {
					Type:        framework.TypeMap,
					Description: "User claims (jwt.UserClaims from github.com/nats-io/jwt/v2)",
					Required:    false,
				},
				"credsTTL": {
					Type:        framework.TypeInt,
					Description: "How long the issued credentials should live for, in seconds",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAddUserIssue,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserIssue,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathDeleteUserIssue,
				},
			},
			HelpSynopsis:    `Manages user cmd's.`,
			HelpDescription: ``,
		},
		{
			Pattern: "issue/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": {
					Type:        framework.TypeString,
					Description: "operator identifier",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "account identifier",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathListUserIssues,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathAddUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	params := IssueUserParameters{}
	json.Unmarshal(jsonString, &params)

	err = addUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(AddingIssueFailedError), nil
	}
	return nil, nil
}

func (b *NatsBackend) pathReadUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueUserParameters{}
	json.Unmarshal(jsonString, &params)

	issue, err := readUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingIssueFailedError), nil
	}

	if issue == nil {
		return logical.ErrorResponse(IssueNotFoundError), nil
	}

	return createResponseIssueUserData(issue)
}

func (b *NatsBackend) pathListUserIssues(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	jsonString, err := json.Marshal(data.Raw)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}
	params := IssueUserParameters{}
	json.Unmarshal(jsonString, &params)

	entries, err := listUserIssues(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListIssuesFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func (b *NatsBackend) pathDeleteUserIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params IssueUserParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	// delete issue and all related nkeys
	err = deleteUserIssue(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(DeleteIssueFailedError), nil
	}
	return nil, nil
}

func addUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {
	log.Info().
		Str("operator", params.Operator).Str("account", params.Account).Str("user", params.User).
		Msgf("issue user")

	// store issue
	issue, err := storeUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}

	return refreshUser(ctx, storage, issue)
}

func refreshUser(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) error {
	// create nkey and signing nkeys
	err := issueUserNKeys(ctx, storage, *issue)
	if err != nil {
		return err
	}

	updateUserStatus(ctx, storage, issue)

	_, err = storeUserIssueUpdate(ctx, storage, issue)
	if err != nil {
		return err
	}

	if issue.User == DefaultPushUser {
		// force update of operator
		// so he gets updates from sys account
		op, err := readOperatorIssue(ctx, storage, IssueOperatorParameters{
			Operator: issue.Operator,
		})
		if err != nil {
			return err
		} else if op == nil {
			log.Warn().Str("operator", issue.Operator).Str("account", issue.Account).Msg("cannot refresh operator: operator issue does not exist")
			return nil
		}

		err = refreshAccountResolvers(ctx, storage, op)
		if err != nil {
			return err
		}
	}
	return nil
}

func readUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)
	return getFromStorage[IssueUserStorage](ctx, storage, path)
}

func listUserIssues(ctx context.Context, storage logical.Storage, params IssueUserParameters) ([]string, error) {
	path := getUserIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}

func deleteUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) error {
	// get stored signing keys
	issue, err := readUserIssue(ctx, storage, params)
	if err != nil {
		return err
	}
	if issue == nil {
		// nothing to delete
		return nil
	}

	// account revocation list handling for deleted user
	account, err := readAccountIssue(ctx, storage, IssueAccountParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return err
	}
	if account != nil {
		// add deleted user to revocation list and update the account JWT
		err = addUserToRevocationList(ctx, storage, account, issue)
		if err != nil {
			return err
		}
	}

	// delete user nkey
	nkey := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	err = deleteUserNkey(ctx, storage, nkey)
	if err != nil {
		return err
	}

	// delete user issue
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)
	return deleteFromStorage(ctx, storage, path)
}

func storeUserIssueUpdate(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) (*IssueUserStorage, error) {
	path := getUserIssuePath(issue.Operator, issue.Account, issue.User)

	err := storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func storeUserIssue(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssueUserStorage, error) {
	path := getUserIssuePath(params.Operator, params.Account, params.User)

	issue, err := getFromStorage[IssueUserStorage](ctx, storage, path)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		issue = &IssueUserStorage{}
	}

	issue.Claims = params.Claims
	issue.Operator = params.Operator
	issue.Account = params.Account
	issue.User = params.User
	issue.UseSigningKey = params.UseSigningKey
	issue.CredsTTL = params.CredsTTL
	err = storeInStorage(ctx, storage, path, issue)
	if err != nil {
		return nil, err
	}
	return issue, nil
}

func issueUserNKeys(ctx context.Context, storage logical.Storage, issue IssueUserStorage) error {
	// issue user nkey
	p := NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	}
	stored, err := readUserNkey(ctx, storage, p)
	if err != nil {
		return err
	}
	if stored == nil {
		err := addUserNkey(ctx, storage, p)
		if err != nil {
			return err
		}
	}
	log.Info().
		Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
		Msg("nkey assigned")
	return nil
}

func issueUserCreds(ctx context.Context, storage logical.Storage, params IssueUserParameters) (*IssuedCreds, error) {
	issue, err := readUserIssue(ctx, storage, params)
	if err != nil {
		return nil, fmt.Errorf("failed to read issue: %w", err)
	}
	if issue == nil {
		return nil, fmt.Errorf("issue not found")
	}

	// use either operator nkey or signing nkey
	// to sign jwt and add issuer claim
	useSigningKey := issue.UseSigningKey
	var seed []byte
	accountNkey, err := readAccountNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
	})
	if err != nil {
		return nil, fmt.Errorf("could not read operator nkey: %s", err)
	}
	if accountNkey == nil {
		log.Warn().
			Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
			Msgf("account nkey does not exist: %s - Cannot create jwt.", issue.Account)
		return nil, fmt.Errorf("account nkey does not exist: %s - Cannot create jwt.", issue.Account)
	}
	accountKeyPair, err := nkeys.FromSeed(accountNkey.Seed)
	if err != nil {
		return nil, err
	}
	accountPublicKey, err := accountKeyPair.PublicKey()
	if err != nil {
		return nil, err
	}
	if useSigningKey == "" {
		seed = accountNkey.Seed
	} else {
		signingNkey, err := readAccountSigningNkey(ctx, storage, NkeyParameters{
			Operator: issue.Operator,
			Account:  issue.Account,
			Signing:  useSigningKey,
		})
		if err != nil {
			return nil, fmt.Errorf("could not read signing nkey: %s", err)
		}
		if signingNkey == nil {
			log.Error().
				Str("operator", issue.Operator).Str("account", issue.Account).Str("user", issue.User).
				Msgf("account signing nkey does not exist: %s - Cannot create jwt.", useSigningKey)
			return nil, fmt.Errorf("account signing nkey does not exist: %s - Cannot create JWT", useSigningKey)
		}
		seed = signingNkey.Seed
	}
	signingKeyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	signingPublicKey, err := signingKeyPair.PublicKey()
	if err != nil {
		return nil, err
	}

	// receive user nkey puplic key
	// to add subject
	data, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err != nil {
		return nil, fmt.Errorf("could not read user nkey: %s", err)
	}
	if data == nil {
		return nil, fmt.Errorf("user nkey does not exist")
	}
	userKeyPair, err := nkeys.FromSeed(data.Seed)
	if err != nil {
		return nil, err
	}
	userPublicKey, err := userKeyPair.PublicKey()
	if err != nil {
		return nil, err
	}
	userSeed, err := userKeyPair.Seed()
	if err != nil {
		return nil, err
	}

	if useSigningKey != "" {
		issue.Claims.IssuerAccount = accountPublicKey
	}

	issue.Claims.ClaimsData.Subject = userPublicKey
	issue.Claims.ClaimsData.Issuer = signingPublicKey

	if issue.CredsTTL > 0 {
		issue.Claims.ClaimsData.Expires = time.Now().Add(time.Duration(issue.CredsTTL) * time.Second).Unix()
	}

	natsJwt, err := v1alpha1.Convert(&issue.Claims)
	if err != nil {
		return nil, fmt.Errorf("could not convert claims to nats jwt: %s", err)
	}
	token, err := natsJwt.Encode(signingKeyPair)
	if err != nil {
		return nil, fmt.Errorf("could not encode jwt: %s", err)
	}

	// format creds
	creds, err := jwt.FormatUserConfig(token, userSeed)
	if err != nil {
		return nil, fmt.Errorf("could not format user creds: %s", err)
	}

	return &IssuedCreds{
		jwt:   token,
		creds: string(creds),
	}, nil
}

func getUserIssuePath(operator string, account string, user string) string {
	return "issue/operator/" + operator + "/account/" + account + "/user/" + user
}

func createResponseIssueUserData(issue *IssueUserStorage) (*logical.Response, error) {
	data := &IssueUserData{
		Operator:      issue.Operator,
		Account:       issue.Account,
		User:          issue.User,
		UseSigningKey: issue.UseSigningKey,
		Claims:        issue.Claims,
		CredsTTL:      issue.CredsTTL,
		Status:        issue.Status,
	}

	rval := map[string]interface{}{}
	err := stm.StructToMap(data, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func updateUserStatus(ctx context.Context, storage logical.Storage, issue *IssueUserStorage) {
	// account status
	nkey, err := readUserNkey(ctx, storage, NkeyParameters{
		Operator: issue.Operator,
		Account:  issue.Account,
		User:     issue.User,
	})
	if err == nil && nkey != nil {
		issue.Status.User.Nkey = true
		issue.Status.User.JWT = true
	} else {
		issue.Status.User.Nkey = false
		issue.Status.User.JWT = false
	}
}
