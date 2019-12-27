package athenz

import (
	"context"
	"crypto/x509"
)

// MockAuthorizerd is a mock for Authorizerd
type MockAuthorizerd struct {
	initErr            error
	verifyRoleTokenErr error
	startErr           error
}

// Init is ...
func (m *MockAuthorizerd) Init(ctx context.Context) error {
	return m.initErr
}

// Start is ...
func (m *MockAuthorizerd) Start(ctx context.Context) <-chan error {
	ch := make(chan error, 1)
	ch <- m.startErr

	return ch
}

// VerifyRoleToken is ...
func (m *MockAuthorizerd) VerifyRoleToken(ctx context.Context, tok, act, res string) error {
	return m.verifyRoleTokenErr
}

// VerifyRoleJWT is ...
func (m *MockAuthorizerd) VerifyRoleJWT(ctx context.Context, tok, act, res string) error {
	return nil
}

// VerifyRoleCert is ...
func (m *MockAuthorizerd) VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error {
	return nil
}

// GetPolicyCache is ...
func (m *MockAuthorizerd) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return nil
}
