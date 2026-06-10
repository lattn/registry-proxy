package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	echo "github.com/labstack/echo/v5"
)

const testImagePrefix = "acme"

var testImages = []string{"agroup/bservice", "cservice"}
var testLocalAuthAccounts = []LocalAuthAccount{{Username: "local-user", Password: "local-pass", Images: testImages}}
var testOtherLocalAuthAccount = LocalAuthAccount{Username: "other-user", Password: "other-pass", Images: []string{"cservice"}}

func TestUpstreamV2Path(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		imagePrefix string
		want        string
		wantOK      bool
	}{
		{name: "catalog root", path: "/v2/", imagePrefix: testImagePrefix, want: "/v2/", wantOK: true},
		{name: "rewrite manifest path", path: "/v2/agroup/bservice/manifests/main", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/bservice/manifests/main", wantOK: true},
		{name: "rewrite blob path", path: "/v2/agroup/bservice/blobs/sha256:abc", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/bservice/blobs/sha256:abc", wantOK: true},
		{name: "rewrite upload root", path: "/v2/agroup/bservice/blobs/uploads/", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/bservice/blobs/uploads/", wantOK: true},
		{name: "rewrite upload session", path: "/v2/agroup/bservice/blobs/uploads/uuid", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/bservice/blobs/uploads/uuid", wantOK: true},
		{name: "rewrite tags list", path: "/v2/agroup/bservice/tags/list", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/bservice/tags/list", wantOK: true},
		{name: "rewrite single segment repository", path: "/v2/cservice/manifests/main", imagePrefix: testImagePrefix, want: "/v2/acme/cservice/manifests/main", wantOK: true},
		{name: "rewrite repository outside allowlist", path: "/v2/agroup/other/manifests/main", imagePrefix: testImagePrefix, want: "/v2/acme/agroup/other/manifests/main", wantOK: true},
		{name: "reject traversal", path: "/v2/agroup/bservice/../manifests/main", imagePrefix: testImagePrefix, wantOK: false},
		{name: "reject non v2 path", path: "/foo/service", imagePrefix: testImagePrefix, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := upstreamV2Path(tt.path, tt.imagePrefix)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriteScopeToUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		scope       string
		imagePrefix string
		want        string
		wantOK      bool
	}{
		{name: "rewrite mapped repository", scope: "repository:agroup/bservice:pull", imagePrefix: testImagePrefix,want: "repository:acme/agroup/bservice:pull", wantOK: true},
		{name: "preserve actions", scope: "repository:agroup/bservice:pull,push", imagePrefix: testImagePrefix,want: "repository:acme/agroup/bservice:pull,push", wantOK: true},
		{name: "rewrite single segment repository", scope: "repository:cservice:pull", imagePrefix: testImagePrefix,want: "repository:acme/cservice:pull", wantOK: true},
		{name: "non repository scope passthrough", scope: "registry:catalog:*", imagePrefix: testImagePrefix,want: "registry:catalog:*", wantOK: true},
		{name: "reject unmapped repository", scope: "repository:agroup/other:pull", imagePrefix: testImagePrefix,wantOK: false},
		{name: "reject traversal", scope: "repository:../service:pull", imagePrefix: testImagePrefix,wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := rewriteScopeToUpstream(tt.scope, tt.imagePrefix, testImages)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriteScopeToLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		scope       string
		imagePrefix string
		want        string
		wantOK      bool
	}{
		{name: "rewrite mapped repository", scope: "repository:acme/agroup/bservice:pull", imagePrefix: testImagePrefix, want: "repository:agroup/bservice:pull", wantOK: true},
		{name: "preserve actions", scope: "repository:acme/agroup/bservice:pull,push", imagePrefix: testImagePrefix, want: "repository:agroup/bservice:pull,push", wantOK: true},
		{name: "rewrite single segment repository", scope: "repository:acme/cservice:pull", imagePrefix: testImagePrefix, want: "repository:cservice:pull", wantOK: true},
		{name: "rewrite repository outside allowlist under prefix", scope: "repository:acme/agroup/other:pull", imagePrefix: testImagePrefix, want: "repository:agroup/other:pull", wantOK: true},
		{name: "reject prefix boundary mismatch", scope: "repository:acmeevil/cservice:pull", imagePrefix: testImagePrefix, wantOK: false},
		{name: "reject malformed repository scope", scope: "repository:acme/agroup/bservice", imagePrefix: testImagePrefix, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := rewriteScopeToLocal(tt.scope, tt.imagePrefix)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriteWWWAuthForLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		request     string
		challenge   string
		imagePrefix string
		assert      func(*testing.T, string, error)
	}{
		{
			name:        "rewrites mapped repository",
			request:     "http://proxy.example/v2/agroup/bservice/manifests/main",
			challenge:   `Bearer realm="https://gitlab.example/jwt/auth",service="container_registry",scope="repository:acme/agroup/bservice:pull"`,
			imagePrefix: testImagePrefix,
			assert: func(t *testing.T, got string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("rewriteWWWAuthForLocal error = %v", err)
				}
				if !strings.HasPrefix(got, `Bearer realm="http://proxy.example/auth?_by=`) {
					t.Fatalf("challenge realm not rewritten: %q", got)
				}
				if !strings.Contains(got, `scope="repository:agroup/bservice:pull"`) {
					t.Fatalf("local scope missing: %q", got)
				}
				if !strings.Contains(got, `service="container_registry"`) {
					t.Fatalf("service parameter missing: %q", got)
				}
			},
		},
		{
			name:        "preserves extra auth params",
			request:     "http://proxy.example/v2/agroup/bservice/manifests/main",
			challenge:   `Bearer realm="https://gitlab.example/jwt/auth",scope="repository:acme/agroup/bservice:pull",service="container_registry"`,
			imagePrefix: testImagePrefix,
			assert: func(t *testing.T, got string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("rewriteWWWAuthForLocal error = %v", err)
				}
				if !strings.Contains(got, `scope="repository:agroup/bservice:pull"`) {
					t.Fatalf("mapped local scope missing: %q", got)
				}
			},
		},
		{
			name:        "rewrites upstream repository outside allowlist",
			request:     "http://proxy.example/v2/agroup/bservice/manifests/main",
			challenge:   `Bearer realm="https://gitlab.example/jwt/auth",scope="repository:acme/agroup/other:pull"`,
			imagePrefix: testImagePrefix,
			assert: func(t *testing.T, got string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("rewriteWWWAuthForLocal error = %v", err)
				}
				if !strings.Contains(got, `scope="repository:agroup/other:pull"`) {
					t.Fatalf("rewritten local scope missing: %q", got)
				}
			},
		},
		{
			name:        "rejects prefix boundary mismatch",
			request:     "http://proxy.example/v2/cservice/manifests/main",
			challenge:   `Bearer realm="https://gitlab.example/jwt/auth",scope="repository:acmeevil/cservice:pull"`,
			imagePrefix: testImagePrefix,
			assert: func(t *testing.T, got string, err error) {
				t.Helper()
				assertHTTPError(t, err, http.StatusForbidden, errForbiddenScope)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", tt.request, nil)
			req.Host = "proxy.example"

			got, err := rewriteWWWAuthForLocal(tt.challenge, req, tt.imagePrefix, "secret")
			tt.assert(t, got, err)
		})
	}
}

func TestParseWWWAuthHandlesCommasInRealm(t *testing.T) {
	t.Parallel()

	u, err := parseWWWAuth(`"https://gitlab.example/jwt/auth?x=1,2",service="container_registry",scope="repository:acme/agroup/bservice:pull"`)
	if err != nil {
		t.Fatalf("parseWWWAuth error = %v", err)
	}

	if u.Scheme != "https" || u.Host != "gitlab.example" {
		t.Fatalf("unexpected auth url: %s", u.String())
	}
	if u.Query().Get("service") != "container_registry" {
		t.Fatalf("service = %q", u.Query().Get("service"))
	}
	if u.Query().Get("scope") != "repository:acme/agroup/bservice:pull" {
		t.Fatalf("scope = %q", u.Query().Get("scope"))
	}
}

func TestBuildWWWAuthChallengeStableOrdering(t *testing.T) {
	t.Parallel()

	params := url.Values{
		"scope":   {"repository:agroup/bservice:pull"},
		"service": {"container_registry"},
	}

	got := buildWWWAuthChallenge("http://proxy.example/auth?_by=abc", params)
	want := `Bearer realm="http://proxy.example/auth?_by=abc",scope="repository:agroup/bservice:pull",service="container_registry"`
	if got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestAuthHandlerRewritesRequestedScopeAndEncryptsToken(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != basicAuthHeader(Credentials{Username: "upstream-user", Password: "upstream-pass"}) {
			t.Fatalf("upstream auth header = %q", got)
		}
		if got := r.URL.Query()["scope"]; len(got) != 1 || got[0] != "repository:acme/agroup/bservice:pull" {
			t.Fatalf("upstream scope = %v", got)
		}
		if got := r.URL.Query().Get("account"); got != "upstream-user" {
			t.Fatalf("upstream account = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "upstream-token"})
	}))
	defer upstream.Close()

	challenge := `Bearer realm="` + upstream.URL + `",service="container_registry",scope="repository:acme/agroup/bservice:pull"`
	by, err := encryptData(strings.TrimPrefix(challenge, "Bearer realm="), "secret")
	if err != nil {
		t.Fatalf("encryptData error = %v", err)
	}

	h := &handler{
		cfg: Config{
			SecurityKey:  "secret",
			ImagePrefix:  testImagePrefix,
			LocalAuth:    testLocalAuthAccounts,
			RegistryAuth: Credentials{Username: "upstream-user", Password: "upstream-pass"},
		},
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/auth?_by="+url.QueryEscape(by)+"&scope=repository:agroup/bservice:pull", nil)
	req.Header.Set("Authorization", basicAuthHeader(Credentials{Username: "local-user", Password: "local-pass"}))
	resp := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, resp)

	if err := h.auth(ctx); err != nil {
		t.Fatalf("auth error = %v", err)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response error = %v", err)
	}

	encryptedToken, _ := body["token"].(string)
	if encryptedToken == "" || encryptedToken == "upstream-token" {
		t.Fatalf("token not rewritten: %q", encryptedToken)
	}
	decryptedToken, err := decryptData(encryptedToken, "secret")
	if err != nil {
		t.Fatalf("decryptData error = %v", err)
	}
	if decryptedToken != "upstream-token" {
		t.Fatalf("token = %q", decryptedToken)
	}
}

func TestProxyV2RewritesBearerTokenAndChallenge(t *testing.T) {
	t.Parallel()

	proxyToken, err := encryptData("upstream-token", "secret")
	if err != nil {
		t.Fatalf("encryptData error = %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/acme/agroup/bservice/manifests/main" {
			t.Fatalf("upstream path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-token" {
			t.Fatalf("upstream bearer token = %q", got)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://gitlab.example/jwt/auth",service="container_registry",scope="repository:acme/agroup/bservice:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	h := &handler{
		cfg: Config{
			SecurityKey: "secret",
			RegistryURL: upstream.URL,
			ImagePrefix: testImagePrefix,
		},
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/agroup/bservice/manifests/main", nil)
	req.Host = "proxy.example"
	req.Header.Set("Authorization", authHeaderBearerPrefix+proxyToken)
	resp := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, resp)

	if err := h.proxyV2(ctx); err != nil {
		t.Fatalf("proxyV2 error = %v", err)
	}
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.Code)
	}

	challenge := resp.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, `Bearer realm="http://proxy.example/auth?_by=`) {
		t.Fatalf("rewritten challenge = %q", challenge)
	}
	if !strings.Contains(challenge, `scope="repository:agroup/bservice:pull"`) {
		t.Fatalf("rewritten scope = %q", challenge)
	}
}

func TestProxyV2RewritesChallengeOutsideConfiguredAllowlist(t *testing.T) {
	t.Parallel()

	proxyToken, err := encryptData("upstream-token", "secret")
	if err != nil {
		t.Fatalf("encryptData error = %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/acme/agroup/other/manifests/main" {
			t.Fatalf("upstream path = %q", r.URL.Path)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://gitlab.example/jwt/auth",service="container_registry",scope="repository:acme/agroup/other:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	h := &handler{
		cfg: Config{
			SecurityKey: "secret",
			RegistryURL: upstream.URL,
			ImagePrefix: testImagePrefix,
		},
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/agroup/other/manifests/main", nil)
	req.Host = "proxy.example"
	req.Header.Set("Authorization", authHeaderBearerPrefix+proxyToken)
	resp := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, resp)

	if err := h.proxyV2(ctx); err != nil {
		t.Fatalf("proxyV2 error = %v", err)
	}
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.Code)
	}
	if got := resp.Header().Get("WWW-Authenticate"); !strings.Contains(got, `scope="repository:agroup/other:pull"`) {
		t.Fatalf("rewritten challenge = %q", got)
	}
}

func TestAuthHandlerRejectsUnmappedRequestedScope(t *testing.T) {
	t.Parallel()

	challenge := `Bearer realm="https://gitlab.example/jwt/auth",service="container_registry",scope="repository:acme/agroup/bservice:pull"`
	by, err := encryptData(strings.TrimPrefix(challenge, "Bearer realm="), "secret")
	if err != nil {
		t.Fatalf("encryptData error = %v", err)
	}

	h := &handler{
		cfg: Config{
			SecurityKey: "secret",
			ImagePrefix: testImagePrefix,
			LocalAuth:   testLocalAuthAccounts,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/auth?_by="+url.QueryEscape(by)+"&scope=repository:agroup/other:pull", nil)
	req.Header.Set("Authorization", basicAuthHeader(Credentials{Username: "local-user", Password: "local-pass"}))
	resp := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, resp)

	err = h.auth(ctx)
	assertHTTPError(t, err, http.StatusForbidden, errForbiddenScope)
}

func TestProxyV2RewritesRepositoryOutsideAllowlist(t *testing.T) {
	t.Parallel()

	got, ok := upstreamV2Path("/v2/agroup/other/manifests/main", testImagePrefix)
	if !ok {
		t.Fatal("expected path rewrite to succeed")
	}
	if got != "/v2/acme/agroup/other/manifests/main" {
		t.Fatalf("path = %q", got)
	}
}

func TestValidateLocalBasicAuthReturnsMatchedAccount(t *testing.T) {
	t.Parallel()

	h := &handler{cfg: Config{LocalAuth: append([]LocalAuthAccount{}, testLocalAuthAccounts[0], testOtherLocalAuthAccount)}}

	account, err := h.validateLocalBasicAuth(basicAuthHeader(Credentials{Username: "other-user", Password: "other-pass"}))
	if err != nil {
		t.Fatalf("validateLocalBasicAuth error = %v", err)
	}
	if account == nil {
		t.Fatal("expected matched account")
	}
	if account.Username != "other-user" {
		t.Fatalf("username = %q", account.Username)
	}
	if len(account.Images) != 1 || account.Images[0] != "cservice" {
		t.Fatalf("images = %v", account.Images)
	}
}

func TestValidateLocalAuthAccountsRejectsDuplicateUsernames(t *testing.T) {
	t.Parallel()

	err := validateLocalAuthAccounts(testImagePrefix, []LocalAuthAccount{
		{Username: "dup", Password: "one", Images: []string{"agroup/bservice"}},
		{Username: "dup", Password: "two", Images: []string{"cservice"}},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicate local auth username "dup"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateLocalAuthAccountsRejectsEmptyImages(t *testing.T) {
	t.Parallel()

	err := validateLocalAuthAccounts(testImagePrefix, []LocalAuthAccount{{Username: "user", Password: "pass"}})
	if err == nil || !strings.Contains(err.Error(), `at least one image is required for "user"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestBasicAuthHeader(t *testing.T) {
	t.Parallel()

	got := basicAuthHeader(Credentials{Username: "user", Password: "pass"})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func assertHTTPError(t *testing.T, err error, status int, message string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("error type = %T, want *echo.HTTPError", err)
	}
	if httpErr.Code != status {
		t.Fatalf("status = %d, want %d", httpErr.Code, status)
	}
	if got := httpErr.Message; got != message {
		t.Fatalf("message = %v, want %q", got, message)
	}
}
