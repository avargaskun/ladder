package handlers

import (
	"net/url"
	"strings"
	"testing"

	"ladder/pkg/ruleset"

	"github.com/stretchr/testify/assert"
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
