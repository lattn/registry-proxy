# registry-proxy

`registry-proxy` is a lightweight proxy service for Docker Registry v2 / OCI Registry. It is useful when you want clients to use a controlled set of local image names while forwarding them to upstream repositories under a fixed prefix and consolidating the upstream authentication flow behind your own entrypoint.

## Typical Use Cases

- Upstream images live under a shared prefix such as `registry.gitlab.com/acme/agroup/bservice`
- You want clients to use stable local names such as `proxy.example.com/agroup/bservice:latest`
- You do not want to expose upstream Registry credentials directly to end users
- You need to restrict access to an explicit allowlist of repositories

## Configuration

By default, the program reads `config.yaml` from the current directory.

See [config.yaml.example](/Users/hao/go/apps/caeret/registry-proxy/config.yaml.example):

```yaml
listen: ":8881"
security_key: "replace-with-a-random-secret"

local_auth:
  - username: "team-a"
    password: "team-a-password"
    images:
      - "agroup/bservice"
  - username: "team-b"
    password: "team-b-password"
    images:
      - "cservice"

registry_url: "https://registry.gitlab.com"
image_prefix: "acme"

registry_auth:
  username: "upstream-user"
  password: "upstream-password"
```

Configuration fields:

- `listen`
  Local listen address, for example `:8881` or `127.0.0.1:8881`.
- `security_key`
  Used to encrypt the `WWW-Authenticate` challenge and Bearer Token. A strong random string is recommended, and it should be kept consistent across all instances.
- `local_auth[].username` / `local_auth[].password`
  Basic Auth credentials used when clients access `/auth`. These are the username and password users enter when logging in to the proxy.
- `local_auth[].images`
  Exact allowlist of local repository names that account may request through `/auth`.
- `registry_url`
  Upstream Registry URL, without a trailing `/`.
- `image_prefix`
  Fixed upstream repository prefix added in front of every requested local repository name.
- `registry_auth.username` / `registry_auth.password`
  Credentials used by the proxy when requesting a token from the upstream `/auth` endpoint. They must have access to the target repositories.

## Quick Start

### 1. Prepare the configuration

```bash
cp config.yaml.example config.yaml
```

Update `config.yaml` to match your environment.

### 2. Start the service

```bash
go run .
```

By default, it listens on:

```text
http://127.0.0.1:8881
```

### 3. Log in to the proxy

```bash
docker login 127.0.0.1:8881
```

Use the username and password from one configured `local_auth` account, not the upstream Registry credentials.

### 4. Pull or push images

If you configure this account:

```yaml
local_auth:
  - username: "team-a"
    password: "team-a-password"
    images:
      - "agroup/bservice"
image_prefix: "acme"
```

Then these commands:

```bash
docker pull 127.0.0.1:8881/agroup/bservice:latest
docker push 127.0.0.1:8881/agroup/bservice:latest
```

Actually operate on:

```text
registry.gitlab.com/acme/agroup/bservice:latest
```

## Access Restrictions

- `proxyV2` forwards local repository paths to `<image_prefix>/<repository>` and rewrites upstream auth challenges back to local repository names
- `/auth` only grants scopes for repositories listed in the authenticated account's `images`
- If a client asks `/auth` for a repository outside that account allowlist, the service returns `403 Forbidden`
- The program rejects suspicious repository paths containing `..`, empty path segments, backslashes, and similar patterns
