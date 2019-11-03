# vault-plugin-auth-athenz
[![CircleCI](https://circleci.com/gh/katyamag/vault-plugin-auth-athenz/tree/master.svg?style=svg)](https://circleci.com/gh/katyamag/vault-plugin-auth-athenz/tree/master)


<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Overview](#overview)
- [How to use](#how-to-use)
  - [Install plugin](#install-plugin)
  - [Prepare vault server(minimun settings)](#prepare-vault-serverminimun-settings)
  - [Register the plugin to Vault](#register-the-plugin-to-vault)
  - [Enable the plugin](#enable-the-plugin)
  - [Check plugins](#check-plugins)
  - [Prepare athenz roletoken](#prepare-athenz-roletoken)
  - [Configuration](#configuration)
  - [Disable and Delete plugin](#disable-and-delete-plugin)
- [Athenz Auth Method (API)](#athenz-auth-method-api)
  - [Create Athenz Role Entry for Vault](#create-athenz-role-entry-for-vault)
  - [Login with Athenz Method](#login-with-athenz-method)
  - [Read Athenz Role Entry](#read-athenz-role-entry)
  - [List Athenz Role Entry](#list-athenz-role-entry)
- [TODO](#todo)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Overview

### Install plugin
```
$ go get ghe.corp.yahoo.co.jp/katyamag/vault-plugin-auth-athenz/cmd/vault-plugin-auth-athenz
```

### Prepare vault server(minimun settings)
__NOTE: Set the `api_addr` to your vault config__

```
$ VAULT_PLUGIN_PATH="/private/tmp/vault-plugins"

$ cat<< EOF | tee /tmp/vault.hcl
log_level = "DEBUG"
api_addr = "http://127.0.0.1:8200"
plugin_directory = "${VAULT_PLUGIN_PATH}"
disable_mlock = true

storage "inmem" {}

listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable = 1
}
EOF
```

Create the config for athenz.
```
$ ATHENZ_URL="https://localhost:4443/zts/v1"
$ ASSERTION_RESOURCE="vault"
$ ASSERTION_ACTION="access"

$ cat<<EOF | tee /tmp/vault/plugin/plugin_config.yaml
---
athenz:
  url: ${ATHENZ_URL}
  policyrhRefreshDuratuon: 6h
  hdr: Athenz-Principal-Auth
  domain: sample.domain
  policy:
    resource: ${ASSERTION_RESOURCE}
    action: ${ASSERTION_ACTION}
EOF
```

### Register the plugin to Vault
```
$ PLUGIN_DIR=$(which vault-plugin-auth-athenz)
$ PLUGIN_CONF_FILE="/tmp/vault/plugin/plugin_conf.yaml"

$ SHA256=$(shasum -a 256 "${PLUGIN_DIR}" | cut -d' ' -f1)
$ vault plugin register -sha256=$SHA256 -args="${PLUGIN_CONF_FILE}" -command=vault-plugin-auth-athenz athenz
```

# Enable plugin
__NOTE: If you don't set the `--options`, this plugin reads the config file from default path `/etc/vault/plugin/athenz_plugin.yaml`.__
```
$ vault auth enable \
-path=athenz \
-plugin-name=athenz \
-options="--config-file=${PLUGIN_CONF_FILE}" \
plugin
```

### Check plugins
```
$ vault auth list
Path       Type      Accessor                Description
----       ----      --------                -----------
athenz/    athenz    auth_athenz_9fd2cac8    n/a
cert/      cert      auth_cert_e990af0b      n/a
token/     token     auth_token_9420f044     token based credentials

$ vault read /sys/plugins/catalog/auth/athenz
Key        Value
---        -----
args       []
builtin    false
command    vault-plugin-auth-athenz
name       athenz
sha256     xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Configuration
1. Configure user with athenz principal that are allowed to authenticate
```
$ vault write auth/athenz/clients/hoge name=hoge role=vault_client_role
```

2. login with athenz n-token
```
$ vault write auth/athenz/login name=hoge token=$NTOKEN
```

### Disable and Delete plugin
```
$ vault auth disable athenz
$ vault delete /sys/plugins/catalog/auth/athenz
```

## Athenz Auth Method (API)

### Create Athenz Role Entry for Vault

| Method | Path                       | Produces         |
|--------|----------------------------|------------------|
| POST   | /auth/athenz/clients/:name | 204 (empty body) |

__Parameters__

---

- `name`: `(string: <required>)` - The name of the vault role
- `ntoken`: `(string: <required>)` - The Ntoken (N-Tokens) for Athenz authorization

__Example__

---

```
$ vault write auth/athenz/clients/hoge \
roletoken=$ROLE_TOKEN \
```

