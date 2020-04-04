package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	// Create directory to place configuration files
	tmpDir, _ := ioutil.TempDir("", "test")
	defer func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Error(err)
		}
	}()
	configPath := filepath.Join(tmpDir, "data.yaml")

	tests := []struct {
		name     string
		data     string
		path     string
		expected *Config
		err      error
	}{
		{
			name: "success",
			data: `---
athenz:
  url: localhost:4443/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`,
			path: configPath,
			expected: &Config{
				Athenz: Athenz{
					URL:                   "localhost:4443/zts/v1",
					PolicyRefreshDuration: "6h",
					Domain:                "sample.domain",
					Policy: Policy{
						Resource: "vault",
						Action:   "access",
					},
				},
			},
			err: nil,
		},
		{
			name: "fail when no such file",
			path: "/no/exist/path/data.yaml",
			err:  fmt.Errorf("open /no/exist/path/data.yaml: no such file or directory"),
		},
		{
			name: "the file is not yaml",
			data: "not yaml",
			path: configPath,
			err:  fmt.Errorf("yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `not yaml` into config.Config"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Prepare for a test configuration file
			if err := ioutil.WriteFile(configPath, []byte(test.data), 0644); err != nil {
				t.Fatalf("faield to write file: %s", err.Error())
			}

			conf, actualErr := NewConfig(test.path)
			if actualErr != nil {
				assert.Equal(t, test.err.Error(), actualErr.Error())
			}
			assert.Exactly(t, test.expected, conf)
		})
	}
}
