package natsbackend

import (
	"context"

	"github.com/NatzkaLabsOpenSource/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathUserCreds(b *NatsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/" + framework.GenericNameRegex("user") + "$",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadUserCreds,
				},
			},
			HelpSynopsis:    `Generate NATS credentials for the user.`,
			HelpDescription: `Generate NATS credentials for the user.`,
		},
		{
			Pattern: "creds/operator/" + framework.GenericNameRegex("operator") + "/account/" + framework.GenericNameRegex("account") + "/user/?$",
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
					Callback: b.pathListUserCreds,
				},
			},
			HelpSynopsis:    "pathRoleListHelpSynopsis",
			HelpDescription: "pathRoleListHelpDescription",
		},
	}
}

func (b *NatsBackend) pathReadUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	params := IssueUserParameters{
		Operator: data.Get("operator").(string),
		Account:  data.Get("account").(string),
		User:     data.Get("user").(string),
	}

	creds, err := issueUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ReadingCredsFailedError), nil
	}

	return createResponseCredsData(creds)
}

func (b *NatsBackend) pathListUserCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := data.Validate()
	if err != nil {
		return logical.ErrorResponse(InvalidParametersError), logical.ErrInvalidRequest
	}

	var params CredsParameters
	err = stm.MapToStruct(data.Raw, &params)
	if err != nil {
		return logical.ErrorResponse(DecodeFailedError), logical.ErrInvalidRequest
	}

	entries, err := listUserCreds(ctx, req.Storage, params)
	if err != nil {
		return logical.ErrorResponse(ListCredsFailedError), nil
	}

	return logical.ListResponse(entries), nil
}

func listUserCreds(ctx context.Context, storage logical.Storage, params CredsParameters) ([]string, error) {
	path := getUserIssuePath(params.Operator, params.Account, "")
	return listIssues(ctx, storage, path)
}
