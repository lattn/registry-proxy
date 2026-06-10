package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/labstack/echo/v5"
)

type handler struct {
	cfg    Config
	client *http.Client
}

const (
	authHeaderBasicPrefix              = "Basic "
	authHeaderBearerPrefix             = "Bearer "
	bearerRealmPrefix                  = "Bearer realm="
	errAuthorizationHeaderMissing      = "Authorization header missing"
	errAuthorizationHeaderInvalid      = "Invalid authorization header"
	errAuthorizationEncodingInvalid    = "Invalid authorization encoding"
	errAuthorizationCredentialsInvalid = "Invalid authorization credentials"
	errAuthChallengeInvalid            = "Invalid auth challenge"
	errBearerTokenInvalid              = "Invalid bearer token"
	errRegistryTokenMissing            = "Registry token missing"
	errForbiddenScope                  = "scope is outside configured image allowlist"
)

func (h *handler) auth(c *echo.Context) error {
	account, err := h.validateLocalBasicAuth(c.Request().Header.Get("Authorization"))
	if err != nil {
		return err
	}

	authURL, err := h.upstreamAuthURL(c, account)
	if err != nil {
		return err
	}

	resp, err := h.doUpstreamAuthRequest(authURL.String())
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return c.NoContent(http.StatusUnauthorized)
	}

	result, err := h.rewriteTokenResponse(resp.Body)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, result)
}

func (h *handler) proxyV2(c *echo.Context) error {
	upstreamURL, err := h.upstreamRegistryURL(c.Request())
	if err != nil {
		return err
	}

	req, err := h.newProxyRequest(c.Request(), upstreamURL)
	if err != nil {
		return err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if err := h.copyProxyResponse(c.Response(), c.Request(), resp); err != nil {
		return err
	}

	return nil
}

func (h *handler) validateLocalBasicAuth(authHeader string) (*LocalAuthAccount, error) {
	if authHeader == "" {
		return nil, unauthorizedError(errAuthorizationHeaderMissing)
	}
	if !strings.HasPrefix(authHeader, authHeaderBasicPrefix) {
		return nil, unauthorizedError(errAuthorizationHeaderInvalid)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, authHeaderBasicPrefix))
	if err != nil {
		return nil, unauthorizedError(errAuthorizationEncodingInvalid)
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, unauthorizedError(errAuthorizationEncodingInvalid)
	}
	for i := range h.cfg.LocalAuth {
		account := &h.cfg.LocalAuth[i]
		if username == account.Username && password == account.Password {
			return account, nil
		}
	}
	return nil, unauthorizedError(errAuthorizationCredentialsInvalid)
}

func (h *handler) upstreamAuthURL(c *echo.Context, account *LocalAuthAccount) (*url.URL, error) {
	wwwAuth, err := decryptData(c.QueryParam("_by"), h.cfg.SecurityKey)
	if err != nil {
		return nil, unauthorizedError(errAuthChallengeInvalid)
	}

	authURL, err := parseWWWAuth(wwwAuth)
	if err != nil {
		return nil, unauthorizedError(errAuthChallengeInvalid)
	}

	query := authURL.Query()
	rewrittenScopes, ok := rewriteScopes(c.QueryParams()["scope"], func(scope string) (string, bool) {
		return rewriteScopeToUpstream(scope, h.cfg.ImagePrefix, account.Images)
	})
	if !ok {
		return nil, forbiddenError(errForbiddenScope)
	}
	if len(rewrittenScopes) > 0 {
		query["scope"] = rewrittenScopes
	}
	query.Set("account", h.cfg.RegistryAuth.Username)
	authURL.RawQuery = query.Encode()
	return authURL, nil
}

func (h *handler) doUpstreamAuthRequest(authURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", basicAuthHeader(h.cfg.RegistryAuth))
	return h.client.Do(req)
}

func (h *handler) rewriteTokenResponse(body io.Reader) (map[string]any, error) {
	var result map[string]any
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, err
	}

	token, _ := result["token"].(string)
	if token == "" {
		token, _ = result["access_token"].(string)
	}
	if token == "" {
		return nil, unauthorizedError(errRegistryTokenMissing)
	}

	encryptedToken, err := encryptData(token, h.cfg.SecurityKey)
	if err != nil {
		return nil, err
	}
	result["token"] = encryptedToken
	if _, ok := result["access_token"]; ok {
		result["access_token"] = encryptedToken
	}
	return result, nil
}

func (h *handler) upstreamRegistryURL(r *http.Request) (string, error) {
	upstreamPath, ok := upstreamV2Path(r.URL.Path, h.cfg.ImagePrefix)
	if !ok {
		return "", forbiddenError(errForbiddenScope)
	}

	upstreamURL := h.cfg.RegistryURL + upstreamPath
	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		upstreamURL += "?" + rawQuery
	}
	return upstreamURL, nil
}

func (h *handler) newProxyRequest(r *http.Request, upstreamURL string) (*http.Request, error) {
	req, err := http.NewRequest(r.Method, upstreamURL, r.Body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.Header {
		req.Header[k] = v
	}

	if err := h.rewriteProxyAuthorization(req); err != nil {
		return nil, err
	}
	return req, nil
}

func (h *handler) rewriteProxyAuthorization(req *http.Request) error {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, authHeaderBearerPrefix) {
		return nil
	}

	token, err := decryptData(strings.TrimPrefix(authHeader, authHeaderBearerPrefix), h.cfg.SecurityKey)
	if err != nil {
		return unauthorizedError(errBearerTokenInvalid)
	}
	req.Header.Set("Authorization", authHeaderBearerPrefix+token)
	return nil
}

func (h *handler) copyProxyResponse(dst http.ResponseWriter, srcReq *http.Request, resp *http.Response) error {
	for headerName := range resp.Header {
		rewrittenValue, rewritten, err := h.rewriteResponseHeader(headerName, resp.Header, srcReq)
		if err != nil {
			return err
		}
		if rewritten {
			dst.Header().Set(headerName, rewrittenValue)
			continue
		}
		for _, value := range resp.Header[headerName] {
			dst.Header().Add(headerName, value)
		}
	}

	dst.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(dst, resp.Body)
	return nil
}

func (h *handler) rewriteResponseHeader(headerName string, headers http.Header, req *http.Request) (string, bool, error) {
	if headerName != "Www-Authenticate" {
		return "", false, nil
	}

	challenge := headers.Get(headerName)
	if !strings.HasPrefix(challenge, bearerRealmPrefix) {
		return "", false, nil
	}

	rewritten, err := rewriteWWWAuthForLocal(challenge, req, h.cfg.ImagePrefix, h.cfg.SecurityKey)
	if err != nil {
		return "", false, err
	}
	return rewritten, true, nil
}

func basicAuthHeader(creds Credentials) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds.Username+":"+creds.Password))
}

func unauthorizedError(message string) error {
	return echo.NewHTTPError(http.StatusUnauthorized, message)
}

func forbiddenError(message string) error {
	return echo.NewHTTPError(http.StatusForbidden, message)
}

func rewriteScopes(scopes []string, rewrite func(string) (string, bool)) ([]string, bool) {
	if len(scopes) == 0 {
		return nil, true
	}

	rewrittenScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		rewritten, ok := rewrite(scope)
		if !ok {
			return nil, false
		}
		rewrittenScopes = append(rewrittenScopes, rewritten)
	}
	return rewrittenScopes, true
}

func encryptData(token, key string) (string, error) {
	cipher, err := aesEncrypt([]byte(token), aesKey([]byte(key)))
	if err != nil {
		return "", err
	}
	return base58.Encode(cipher), nil
}

func decryptData(token, key string) (string, error) {
	cipher, err := aesDecrypt(base58.Decode(token), aesKey([]byte(key)))
	if err != nil {
		return "", err
	}
	return string(cipher), nil
}

func parseWWWAuth(wwwAuth string) (*url.URL, error) {
	fields := splitChallengeFields(wwwAuth)
	if len(fields) == 0 {
		return nil, errors.New("empty auth challenge")
	}

	authURL, err := url.Parse(strings.Trim(fields[0], `"`))
	if err != nil {
		return nil, err
	}

	query := authURL.Query()
	for _, field := range fields[1:] {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) != 2 {
			continue
		}
		key := strings.TrimSpace(pair[0])
		value := strings.Trim(strings.TrimSpace(pair[1]), `"`)
		if key != "" {
			query.Add(key, value)
		}
	}

	authURL.RawQuery = query.Encode()
	return authURL, nil
}

func rewriteScopeToUpstream(scope, imagePrefix string, images []string) (string, bool) {
	const repositoryPrefix = "repository:"
	if !strings.HasPrefix(scope, repositoryPrefix) {
		return scope, true
	}

	name, actions, ok := splitRepositoryScope(scope)
	if !ok || !isSafeRepositoryPath(name) {
		return "", false
	}

	target, ok := localToUpstreamRepository(imagePrefix, images, name)
	if !ok {
		return "", false
	}
	return repositoryPrefix + target + ":" + actions, true
}

func rewriteScopeToLocal(scope, imagePrefix string) (string, bool) {
	const repositoryPrefix = "repository:"
	if !strings.HasPrefix(scope, repositoryPrefix) {
		return scope, true
	}

	name, actions, ok := splitRepositoryScope(scope)
	if !ok || !isSafeRepositoryPath(name) {
		return "", false
	}

	source, ok := upstreamToLocalRepository(imagePrefix, name)
	if !ok {
		return "", false
	}
	return repositoryPrefix + source + ":" + actions, true
}

func splitRepositoryScope(scope string) (string, string, bool) {
	rest := strings.TrimPrefix(scope, "repository:")
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func upstreamV2Path(requestPath, imagePrefix string) (string, bool) {
	if requestPath == "/v2" || requestPath == "/v2/" {
		return "/v2/", true
	}
	if !strings.HasPrefix(requestPath, "/v2/") {
		return "", false
	}

	repository, suffix, ok := splitV2RepositoryPath(strings.TrimPrefix(requestPath, "/v2/"))
	if !ok {
		return "", false
	}
	if repository == "" {
		return "/v2/" + suffix, true
	}

	target := imagePrefix + "/" + repository
	if !isSafeRepositoryPath(target) {
		return "", false
	}
	return "/v2/" + target + suffix, true
}

func isSafeRepositoryPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, `\`) {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func rewriteWWWAuthForLocal(wwwAuth string, r *http.Request, imagePrefix, key string) (string, error) {
	payload := strings.TrimPrefix(wwwAuth, bearerRealmPrefix)

	by, err := encryptData(payload, key)
	if err != nil {
		return "", err
	}

	authURL, err := parseWWWAuth(payload)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	rewrittenScopes, ok := rewriteScopes(query["scope"], func(scope string) (string, bool) {
		return rewriteScopeToLocal(scope, imagePrefix)
	})
	if !ok {
		return "", forbiddenError(errForbiddenScope)
	}
	if len(rewrittenScopes) > 0 {
		query["scope"] = rewrittenScopes
	}

	return buildWWWAuthChallenge(localAuthEndpoint(r, by), query), nil
}

func localToUpstreamRepository(imagePrefix string, images []string, repository string) (string, bool) {
	if !isAllowedLocalRepository(images, repository) {
		return "", false
	}
	upstream := imagePrefix + "/" + repository
	if !isSafeRepositoryPath(upstream) {
		return "", false
	}
	return upstream, true
}

func upstreamToLocalRepository(imagePrefix, repository string) (string, bool) {
	prefix := imagePrefix + "/"
	if !strings.HasPrefix(repository, prefix) {
		return "", false
	}
	local := strings.TrimPrefix(repository, prefix)
	if !isSafeRepositoryPath(local) {
		return "", false
	}
	return local, true
}

func isAllowedLocalRepository(images []string, repository string) bool {
	for _, image := range images {
		if image == repository {
			return true
		}
	}
	return false
}

func splitV2RepositoryPath(path string) (string, string, bool) {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return "", "", false
	}

	markers := []string{
		"/manifests/",
		"/blobs/uploads/",
		"/blobs/",
		"/tags/list",
		"/referrers/",
	}
	for _, marker := range markers {
		if idx := strings.Index(path, marker); idx > 0 {
			repository := path[:idx]
			suffix := path[idx:]
			if !isSafeRepositoryPath(repository) || !isSafeV2ActionPath(suffix) {
				return "", "", false
			}
			return repository, suffix, true
		}
	}
	return "", "", false
}

func isSafeV2ActionPath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func splitChallengeFields(s string) []string {
	fields := make([]string, 0, 4)
	start := 0
	inQuotes := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	fields = append(fields, strings.TrimSpace(s[start:]))
	return fields
}

func buildWWWAuthChallenge(realm string, params url.Values) string {
	var b strings.Builder
	b.WriteString(bearerRealmPrefix)
	b.WriteString(strconv.Quote(realm))

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		for _, value := range params[key] {
			b.WriteString(",")
			b.WriteString(key)
			b.WriteString("=")
			b.WriteString(strconv.Quote(value))
		}
	}

	return b.String()
}

func localAuthEndpoint(r *http.Request, by string) string {
	scheme := "http"
	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		scheme = forwardedProto
	} else if r.TLS != nil {
		scheme = "https"
	}

	return scheme + "://" + host + "/auth?_by=" + by
}
