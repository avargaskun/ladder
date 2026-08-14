package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ladder/pkg/ruleset"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ruleFromYAML builds a ruleset.Rule from its real on-disk YAML shape. Rule's
// Injections/Headers/URLMods are anonymous inline structs, so a composite
// literal would have to restate every yaml tag verbatim.
func ruleFromYAML(t *testing.T, y string) ruleset.Rule {
	t.Helper()
	var rs ruleset.RuleSet
	if err := yaml.Unmarshal([]byte(y), &rs); err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rs))
	}
	return rs[0]
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// withRulesSet swaps the package-level rulesSet for the duration of a test.
func withRulesSet(t *testing.T, rs ruleset.RuleSet) {
	t.Helper()
	prev := rulesSet
	rulesSet = rs
	t.Cleanup(func() { rulesSet = prev })
}

const sampleHTML = `<html><head><title>t</title></head><body><p>Example Domain</p></body></html>`

func TestApplyRulesInjectsIntoHead(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  injections:
    - position: head
      append: "<!--CANARY-->"
`)
	got := applyRules(sampleHTML, rule)
	assert.Contains(t, got, "CANARY")
}

func TestApplyRulesRegexSubstitutes(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  regexRules:
    - match: "Example Domain"
      replace: "REPLACED"
`)
	got := applyRules(sampleHTML, rule)
	assert.Contains(t, got, "REPLACED")
	assert.NotContains(t, got, "Example Domain")
}

func TestApplyRulesPrependAndReplace(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  injections:
    - position: body
      prepend: "<div id=\"PREPENDED\"></div>"
    - position: title
      replace: "<title>REPLACED-TITLE</title>"
`)
	got := applyRules(sampleHTML, rule)
	assert.Contains(t, got, "PREPENDED")
	assert.Contains(t, got, "REPLACED-TITLE")
	assert.NotContains(t, got, "<title>t</title>")
}

// Guards the P3 hardening: upstream used regexp.MustCompile on rule-supplied
// patterns, so one bad rule panicked the request handler.
func TestApplyRulesInvalidRegexDoesNotPanic(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  regexRules:
    - match: "(["
      replace: "x"
`)
	assert.NotPanics(t, func() {
		got := applyRules(sampleHTML, rule)
		assert.Equal(t, sampleHTML, got)
	})
}

// Guards against the removed log.Fatal: a body goquery struggles with must
// degrade that one response, never exit the process.
func TestApplyRulesMalformedDocumentDoesNotExit(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  injections:
    - position: head
      append: "<!--CANARY-->"
`)
	malformed := "<<<not really html<<< \x00 <p unterminated"
	var got string
	assert.NotPanics(t, func() { got = applyRules(malformed, rule) })
	assert.NotEmpty(t, got)
}

// The end-to-end proof that the call site restored in rewriteHtml is wired.
// This is the F4 differential: it fails on stock v0.0.23.
func TestRewriteHtmlAppliesRules(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  injections:
    - position: head
      append: "<!--LADDER-INJECTION-CANARY-->"
  regexRules:
    - match: "Example Domain"
      replace: "Example Domain [LADDER-REGEX-CANARY]"
`)
	withRulesSet(t, ruleset.RuleSet{rule})

	got := rewriteHtml([]byte(sampleHTML), mustParseURL(t, "https://example.com/"), rule)
	assert.Contains(t, got, "LADDER-INJECTION-CANARY")
	assert.Contains(t, got, "LADDER-REGEX-CANARY")
}

// Pins the P2 gate: the call site keys off len(rulesSet), not os.Getenv("RULESET").
func TestRewriteHtmlNoRulesetLeavesBodyAlone(t *testing.T) {
	rule := ruleFromYAML(t, `
- domain: example.com
  injections:
    - position: head
      append: "<!--LADDER-INJECTION-CANARY-->"
`)
	withRulesSet(t, ruleset.RuleSet{})

	got := rewriteHtml([]byte(sampleHTML), mustParseURL(t, "https://example.com/"), rule)
	assert.NotContains(t, got, "LADDER-INJECTION-CANARY")
	assert.True(t, strings.Contains(got, "Example Domain"))
}

// ---------------------------------------------------------------------------
// Phase 2: SSRF guard, FlareSolverr exemption, extractUrl contract
// ---------------------------------------------------------------------------

func TestIsDisallowedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"::1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.4.1",
		"169.254.1.1",
		"fc00::1",
		"0.0.0.0",
		// The CGNAT cases are the regression guard: they pass only because the
		// guard knows about 100.64.0.0/10. An IsPrivate()-only implementation
		// lets the whole tailnet through, traefik included.
		"100.110.42.49",
		"100.64.0.1",
		"100.127.255.254",
	}
	allowed := []string{
		"93.184.216.34",
		"1.1.1.1",
		"100.63.255.255",
		"100.128.0.1",
		"2606:2800:220:1:248:1893:25c8:1946",
	}

	for _, s := range blocked {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, "could not parse %q", s)
		assert.True(t, isDisallowedIP(ip), "expected %s to be disallowed", s)
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		require.NotNil(t, ip, "could not parse %q", s)
		assert.False(t, isDisallowedIP(ip), "expected %s to be allowed", s)
	}
}

// The redirect chain needs no separate test: every hop is dialled through
// safeDialContext, so a 302 to a private address fails exactly like this.
func TestSafeTransportBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: safeTransport}
	resp, err := client.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked request to non-public address")
}

func TestSafeTransportBlocksHostnameResolvingToPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u := mustParseURL(t, srv.URL)
	byName := "http://localhost:" + u.Port() + "/"

	client := &http.Client{Transport: safeTransport}
	resp, err := client.Get(byName)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked request to non-public address")
}

// Mis-wiring is the realistic failure mode, so assert it functionally: a
// fetchSite whose client does not carry safeTransport happily fetches loopback.
func TestFetchSiteUsesGuardedTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>should never be reachable</body></html>"))
	}))
	defer srv.Close()

	body, _, _, err := fetchSite(srv.URL, nil)
	require.Error(t, err)
	assert.Empty(t, body)
	assert.Contains(t, err.Error(), "blocked request to non-public address")
}

// The regression guard for the single most likely way to break FlareSolverr:
// someone later "tidying up" by putting safeTransport on this client too.
// FlareSolverr is a sibling container on a private address by design.
func TestGetFlareSolverrCookiesReachesPrivateAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","solution":{"cookies":[{"name":"cf_clearance","value":"abc"}]}}`))
	}))
	defer srv.Close()

	prev := flareSolverrHost
	flareSolverrHost = srv.URL
	t.Cleanup(func() { flareSolverrHost = prev })

	got, err := getFlareSolverrCookies("https://example.com")
	require.NoError(t, err)
	assert.Equal(t, "cf_clearance=abc", got)
}

// extractUrlFromPath drives extractUrl through a real Fiber app so the "*"
// param is populated exactly as it is in production.
func extractUrlFromPath(t *testing.T, path string, headers map[string]string) (string, error) {
	t.Helper()
	app := fiber.New()
	var got string
	var gotErr error
	app.Get("/*", func(c *fiber.Ctx) error {
		got, gotErr = extractUrl(c)
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	resp.Body.Close()
	return got, gotErr
}

func TestExtractUrlFullyEncoded(t *testing.T) {
	got, err := extractUrlFromPath(t, "/https%3A%2F%2Fexample.com/article", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/article", got)
}

func TestExtractUrlSlashesEncodedOnly(t *testing.T) {
	got, err := extractUrlFromPath(t, "/https:%2F%2Fexample.com/article", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/article", got)
}

// F1: the Traefik-collapsed form. Traefik normalises "//" to "/" in a path, so
// an unencoded "https://example.com/..." arrives as "https:/example.com/...",
// hostless once parsed. extractUrl repairs it; clients should still send the
// percent-encoded form, but a decoding hop upstream (an Authelia login round
// trip re-decodes the path) can strip that encoding out of their control.
func TestExtractUrlCollapsedSlashesRepaired(t *testing.T) {
	got, err := extractUrlFromPath(t, "/https:/example.com/article", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/article", got)
}

// The exact shape the Authelia round trip produces (2026-08-14 incident): every
// path-legal escape decoded, "?" left as %3F, "//" then collapsed by Traefik.
func TestExtractUrlAutheliaRoundTripShapeRepaired(t *testing.T) {
	got, err := extractUrlFromPath(t, "/https:/example.com/post/1%3Futm_medium=social&utm_campaign=x", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/post/1?utm_medium=social&utm_campaign=x", got)
}

// F1b: a relative sub-resource is reconstructed from the Referer header.
func TestExtractUrlRelativePathUsesReferer(t *testing.T) {
	got, err := extractUrlFromPath(t, "/images/foobar.jpg", map[string]string{
		"Referer": "http://ladder.vargas.casa/https://example.com/article",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/images/foobar.jpg", got)
}

// F7: the same-origin rewrite must percent-encode the scheme separator, or
// every rewritten reference arrives at the backend Traefik-collapsed
// (extractUrl now repairs that form, but only encoding is byte-stable).
func TestRewriteHtmlEncodesSchemeSeparator(t *testing.T) {
	body := rewriteHtml([]byte(`<a href="/post/1">x</a><img src="/a.png"><link href="/a.css">`),
		mustParseURL(t, "https://example.com/article"), ruleset.Rule{})

	assert.NotContains(t, body, `"/https://`, "unencoded separator survives a slash-collapsing proxy only by luck")
	assert.Contains(t, body, `href="/https%3A%2F%2Fexample.com/post/1"`)
	assert.Contains(t, body, `src="/https%3A%2F%2Fexample.com/a.png"`)
	assert.Contains(t, body, `href="/https%3A%2F%2Fexample.com/a.css"`)
}

// F8: a protocol-relative reference is cross-origin. Treating its leading "//"
// as a root-relative path folds the asset onto the article's own host, where it
// resolves to that site's soft-404 HTML - which a browser then refuses as a
// stylesheet, rendering the whole page unstyled.
func TestRewriteHtmlProtocolRelativeKeepsItsOwnHost(t *testing.T) {
	body := rewriteHtml([]byte(`<link rel="stylesheet" href="//assets.cdn.net/main.css"><img src="//img.cdn.net/a.png">`),
		mustParseURL(t, "https://example.com/article"), ruleset.Rule{})

	assert.Contains(t, body, `href="/https%3A%2F%2Fassets.cdn.net/main.css"`)
	assert.Contains(t, body, `src="/https%3A%2F%2Fimg.cdn.net/a.png"`)
	assert.NotContains(t, body, "example.com//", "the CDN host was folded onto the article origin")
}

// The absolute same-origin form used to gain a stray slash after the host.
func TestRewriteHtmlAbsoluteSameOriginHref(t *testing.T) {
	body := rewriteHtml([]byte(`<a href="https://example.com/post/1">x</a><a href="https://example.com">home</a>`),
		mustParseURL(t, "https://example.com/article"), ruleset.Rule{})

	assert.Contains(t, body, `href="/https%3A%2F%2Fexample.com/post/1"`)
	assert.Contains(t, body, `href="/https%3A%2F%2Fexample.com"`)
	assert.NotContains(t, body, "example.com//")
}

// CSS url() references, quoted and bare, root- and protocol-relative.
func TestRewriteHtmlCSSUrlRefs(t *testing.T) {
	body := rewriteHtml([]byte(`a{background:url(/bg.png)}b{background:url('/c.png')}c{background:url(//cdn.net/d.png)}`),
		mustParseURL(t, "https://example.com/article"), ruleset.Rule{})

	assert.Contains(t, body, `url(/https%3A%2F%2Fexample.com/bg.png)`)
	assert.Contains(t, body, `url('/https%3A%2F%2Fexample.com/c.png')`)
	assert.Contains(t, body, `url(/https%3A%2F%2Fcdn.net/d.png)`)
}

// The rewritten form must survive the round trip back through extractUrl.
func TestRewriteHtmlOutputRoundTripsThroughExtractUrl(t *testing.T) {
	body := rewriteHtml([]byte(`<link href="//assets.cdn.net/main.css">`),
		mustParseURL(t, "https://example.com/article"), ruleset.Rule{})

	path := strings.TrimSuffix(strings.SplitN(body, `href="`, 2)[1], `">`)
	got, err := extractUrlFromPath(t, path, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://assets.cdn.net/main.css", got)
}
