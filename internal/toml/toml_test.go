// Tests for the TOML subset parser. Every accepted construct that a persona
// file can legally contain is covered, plus the explicit rejections — the
// parser must fail loudly on TOML features it does not implement rather
// than misparse them.
package toml

import (
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, src string) map[string]any {
	t.Helper()
	m, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", src, err)
	}
	return m
}

func parseErr(t *testing.T, src, wantSubstr string) {
	t.Helper()
	_, err := Parse(src)
	if err == nil {
		t.Fatalf("Parse(%q) unexpectedly succeeded", src)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("Parse(%q) error %q does not mention %q", src, err, wantSubstr)
	}
}

func TestParseScalarValues(t *testing.T) {
	cases := map[string]any{
		`s = "alice"`:           "alice",
		`s = "a\tb\nc\"d\\eé"`:  "a\tb\nc\"d\\eé",
		`s = 'C:\keys\dev.pem'`: `C:\keys\dev.pem`, // literal strings keep backslashes
		"s = 1_000_000":         int64(1000000),
		"s = -42":               int64(-42),
		"s = 3.5":               3.5,
		"s = true":              true,
		"s = false":             false,
	}
	for src, want := range cases {
		if got := parse(t, src)["s"]; got != want {
			t.Errorf("%s => %#v, want %#v", src, got, want)
		}
	}
}

func TestParseArrays(t *testing.T) {
	m := parse(t, `groups = ["admin", "dev"]`)
	if !reflect.DeepEqual(m["groups"], []any{"admin", "dev"}) {
		t.Fatalf("got %#v", m["groups"])
	}
	// Multi-line array with comments and a trailing comma — the shape every
	// redirect_uris list ends up in.
	m = parse(t, "uris = [\n  \"http://127.0.0.1:3000/cb\", # dev\n  \"http://127.0.0.1:4000/cb\",\n]\n")
	want := []any{"http://127.0.0.1:3000/cb", "http://127.0.0.1:4000/cb"}
	if !reflect.DeepEqual(m["uris"], want) {
		t.Fatalf("got %#v", m["uris"])
	}
	m = parse(t, `matrix = [[1, 2], [3]]`)
	if !reflect.DeepEqual(m["matrix"], []any{[]any{int64(1), int64(2)}, []any{int64(3)}}) {
		t.Fatalf("got %#v", m["matrix"])
	}
}

func TestParseTableAndDottedHeader(t *testing.T) {
	m := parse(t, "[tokens]\nttl = \"1h\"\n[a.b]\nc = 1\n")
	tokens := m["tokens"].(map[string]any)
	if tokens["ttl"] != "1h" {
		t.Fatalf("got %#v", tokens)
	}
	if m["a"].(map[string]any)["b"].(map[string]any)["c"] != int64(1) {
		t.Fatalf("got %#v", m["a"])
	}
}

func TestParseArrayOfTables(t *testing.T) {
	src := "[[personas]]\nname = \"alice\"\n[[personas]]\nname = \"bob\"\n"
	arr := parse(t, src)["personas"].([]any)
	if len(arr) != 2 {
		t.Fatalf("want 2 personas, got %d", len(arr))
	}
	if arr[0].(map[string]any)["name"] != "alice" || arr[1].(map[string]any)["name"] != "bob" {
		t.Fatalf("got %#v", arr)
	}
}

func TestParseSubtableOfArrayElementAttachesToLastElement(t *testing.T) {
	// [personas.claims] after [[personas]] must land on the most recent
	// persona — this is exactly how persona files declare custom claims.
	src := "[[personas]]\nname = \"alice\"\n[personas.claims]\nrole = \"admin\"\n[[personas]]\nname = \"bob\"\n"
	arr := parse(t, src)["personas"].([]any)
	claims := arr[0].(map[string]any)["claims"].(map[string]any)
	if claims["role"] != "admin" {
		t.Fatalf("got %#v", claims)
	}
	if _, ok := arr[1].(map[string]any)["claims"]; ok {
		t.Fatal("claims leaked onto the second persona")
	}
}

func TestParseKeys(t *testing.T) {
	// Dotted keys create intermediate tables under the current table.
	m := parse(t, "[tokens]\nlimits.max = 10\n")
	if m["tokens"].(map[string]any)["limits"].(map[string]any)["max"] != int64(10) {
		t.Fatalf("got %#v", m["tokens"])
	}
	if parse(t, `"weird key" = 1`)["weird key"] != int64(1) {
		t.Fatal("quoted key lost")
	}
	for key, want := range map[string]bool{
		"alice": true, "a-b_c9": true, "": false, "has space": false, "café": false,
	} {
		if got := IsBareKey(key); got != want {
			t.Errorf("IsBareKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestParseCommentsBlankLinesAndEmptyDocument(t *testing.T) {
	m := parse(t, "# header comment\n\nname = \"x\"  # trailing\n\n# footer\n")
	if m["name"] != "x" {
		t.Fatalf("got %#v", m)
	}
	if m := parse(t, "\n# only a comment\n"); len(m) != 0 {
		t.Fatalf("got %#v", m)
	}
}

func TestStructuralConflictsRejected(t *testing.T) {
	parseErr(t, "a = 1\na = 2\n", `key "a" is set twice`)
	parseErr(t, "[t]\na = 1\n[t]\nb = 2\n", "defined twice")
	parseErr(t, "a = [1]\n[[a]]\nb = 2\n", "cannot extend")
}

func TestErrorsCarryLineNumbers(t *testing.T) {
	parseErr(t, "ok = 1\nbad = \"oops\n", "line 2")
	// Newlines inside a multi-line array still advance the line counter.
	parseErr(t, "arr = [\n 1,\n 2,\n]\nbad =\n", "line 5")
	parseErr(t, `a = 1 extra`, "unexpected characters after value")
}

func TestUnsupportedFeaturesRejectedWithHints(t *testing.T) {
	// The single most likely user mistake in an issued_at line: forgetting
	// the quotes. The error must say what to do.
	parseErr(t, "issued_at = 2026-01-01T00:00:00Z", "quote the timestamp")
	parseErr(t, `claims = { role = "admin" }`, "use a [table] section")
	parseErr(t, "s = \"\"\"x\"\"\"", "multi-line strings")
}
