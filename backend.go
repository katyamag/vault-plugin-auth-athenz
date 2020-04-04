/*
 *athenzauth is a plugin for vault using athenz
 */
package athenzauth

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
)

const (
	backendHelp = `
The "athenz" credential provider allows authentication using Athenz.
`
)

type athenzAuthBackend struct {
	*framework.Backend

	l *sync.RWMutex

	updaterCtx       context.Context
	updaterCtxCancel context.CancelFunc
}

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	confPath := ""

	if p, ok := c.Config["--config-file"]; ok {
		confPath = p
	}
	if confPath == "" {
		return nil, errors.New("athenz config path is empty")
	}

	b, err := backend(confPath)
	if err != nil {
		return nil, err
	}

	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func backend(confPath string) (*athenzAuthBackend, error) {
	var b athenzAuthBackend
	b.updaterCtx, b.updaterCtxCancel = context.WithCancel(context.Background())

	conf, err := config.NewConfig(confPath)
	if err != nil {
		return nil, err
	}

	if err := athenz.NewValidator(conf.Athenz); err != nil {
		return nil, err
	}

	// Initialize validator
	if err := athenz.GetValidator().Init(b.updaterCtx); err != nil {
		return nil, err
	}

	// Start validator
	athenz.GetValidator().Start(b.updaterCtx)

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeCredential,
		// AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfigClient(&b),
				pathLogin(&b),
				pathListClients(&b),
			},
		),
	}

	b.l = &sync.RWMutex{}

	return &b, nil
}
