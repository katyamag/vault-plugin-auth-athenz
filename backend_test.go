package athenzauth

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	hlog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
)

const (
	basicConfig = `---
athenz:
  url: https://test.athenz.com/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`

	invalidConfig = `---
athenz:
  invalid
  url: https://test.athenz.com/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`

	invalidAthenzParamConfig = `---
athenz:
  url: https://test.athenz.com/zts/v1
  domain: -01domain
`
)

func createTestAthenzConfig(data []byte) (string, string, error) {
	// Create directory to place configuration files
	tmpDir, _ := ioutil.TempDir("", "test")
	configFilePath := filepath.Join(tmpDir, "data.yaml")

	return tmpDir, configFilePath, ioutil.WriteFile(configFilePath, data, 0644)
}

func TestFactory_Create(t *testing.T) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	tests := []struct {
		name         string
		athenzConfig []byte
		withoutPath  bool
		athenz.MockAthenz
		expectedErr string
	}{
		{
			name:         "without config path",
			athenzConfig: []byte(basicConfig),
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "athenz config path not set",
		},
		{
			name:         "invalid config",
			athenzConfig: []byte(invalidConfig),
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "yaml: line 4: mapping values are not allowed in this context",
		},
		{
			name:         "failed to initialize athenz validator",
			athenzConfig: []byte(basicConfig),
			MockAthenz: athenz.MockAthenz{
				InitErr: errors.New("failed"),
			},
			expectedErr: "failed",
		},
		{
			name:         "failed to create validator instance because of invalid url",
			athenzConfig: []byte(invalidAthenzParamConfig),
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "invalid athenz domain",
		},
		{
			name:         "fail when config path is empty",
			athenzConfig: []byte(invalidAthenzParamConfig),
			withoutPath:  true,
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "athenz config path is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, path, err := createTestAthenzConfig(tt.athenzConfig)
			if err != nil {
				t.Fatalf("createTestAthenz: %s", err.Error())
			}
			defer func() {
				err := os.RemoveAll(tmpDir)
				if err != nil {
					t.Error(err)
				}
			}()
			athenz.SetMockAthenz(&tt.MockAthenz)

			backendConfig := &logical.BackendConfig{
				Config: map[string]string{
					"--config-file": func() string {
						if tt.withoutPath {
							return ""
						}
						return path
					}(),
				},
				Logger: logging.NewVaultLogger(hlog.Trace),
				System: &logical.StaticSystemView{
					DefaultLeaseTTLVal: defaultLeaseTTLVal,
					MaxLeaseTTLVal:     maxLeaseTTLVal,
				},
				StorageView: &logical.InmemStorage{},
			}

			_, actual := Factory(context.Background(), backendConfig)
			if actual != nil && actual.Error() != tt.expectedErr {
				t.Errorf("Factory() actual = %v, expected = %v", actual, tt.expectedErr)
			}
		})
	}
}

// func TestSetConfigPath(t *testing.T) {
//   path := "/tmp/config.hcl"
//   SetConfigPath(path)
//   assert.Equal(t, path, confPath)

//   path = "/etc/test/path"
//   SetConfigPath(path)
//   assert.Equal(t, path, confPath)
// }
