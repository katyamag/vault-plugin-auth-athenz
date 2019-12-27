package athenz

import (
	"context"

	"github.com/yahoo/athenz/clients/go/zts"
)

// Athenz is interface for athenz setting or daemon
type Athenz interface {
	Init(context.Context) error
	Start(context.Context) <-chan error
	VerifyToken(context.Context, string, string) (*zts.RoleToken, error)
}
