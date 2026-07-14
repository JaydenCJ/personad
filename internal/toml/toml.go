// Package toml implements the well-defined TOML subset personad uses for
// persona files: comments, bare/quoted keys, dotted keys, basic and literal
// strings, integers, floats, booleans, (nested, multi-line) arrays, tables
// and arrays of tables. It is deliberately small, has zero dependencies,
// and reports every error with a line number.
//
// Unsupported on purpose (rejected with a clear error, never silently
// misparsed): multi-line strings, inline tables, and bare datetimes —
// persona files express timestamps as RFC 3339 strings.
package toml

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Parse decodes TOML source into a tree of map[string]any, []any, string,
// int64, float64 and bool values. Arrays of tables become []any holding
// map[string]any elements.
func Parse(src string) (map[string]any, error) {
	p := &parser{src: src, line: 1}
	root := map[string]any{}
	p.root = root
	p.current = root

	for {
		p.skipBlank()
		if p.eof() {
			return root, nil
		}
		var err error
		switch {
		case p.peek() == '[':
			err = p.parseTableHeader()
		default:
			err = p.parseKeyValue()
		}
		if err != nil {
			return nil, err
		}
	}
}

type parser struct {
	src     string
	pos     int
	line    int
	root    map[string]any
	current map[string]any
	// explicit remembers [table] headers already seen, to reject duplicates.
	explicit map[string]bool
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("toml: line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func (p *parser) eof() bool { return p.pos >= len(p.src) }

func (p *parser) peek() byte { return p.src[p.pos] }

func (p *parser) advance() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

// skipBlank consumes whitespace, newlines and full-line/trailing comments.
func (p *parser) skipBlank() {
	for !p.eof() {
		c := p.peek()
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.advance()
		case c == '#':
			for !p.eof() && p.peek() != '\n' {
				p.advance()
			}
		default:
			return
		}
	}
}

// skipInlineSpace consumes spaces and tabs only (not newlines).
func (p *parser) skipInlineSpace() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

// expectLineEnd requires nothing but whitespace/comment before the newline.
func (p *parser) expectLineEnd() error {
	p.skipInlineSpace()
	if p.eof() {
		return nil
	}
	switch p.peek() {
	case '\n':
		p.advance()
		return nil
	case '\r':
		p.advance()
		if !p.eof() && p.peek() == '\n' {
			p.advance()
		}
		return nil
	case '#':
		for !p.eof() && p.peek() != '\n' {
			p.advance()
		}
		return nil
	}
	return p.errf("unexpected characters after value: %q", p.restOfLine())
}

func (p *parser) restOfLine() string {
	end := strings.IndexByte(p.src[p.pos:], '\n')
	if end < 0 {
		return p.src[p.pos:]
	}
	return strings.TrimRight(p.src[p.pos:p.pos+end], "\r")
}

// --- keys ---------------------------------------------------------------

func isBareKeyChar(c byte) bool {
	return c == '-' || c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// parseKeyPath reads a possibly dotted key such as `tokens.ttl` or `"a b".c`.
func (p *parser) parseKeyPath() ([]string, error) {
	var path []string
	for {
		p.skipInlineSpace()
		if p.eof() {
			return nil, p.errf("unexpected end of input in key")
		}
		var part string
		switch c := p.peek(); {
		case c == '"':
			s, err := p.parseBasicString()
			if err != nil {
				return nil, err
			}
			part = s
		case c == '\'':
			s, err := p.parseLiteralString()
			if err != nil {
				return nil, err
			}
			part = s
		case isBareKeyChar(c):
			start := p.pos
			for !p.eof() && isBareKeyChar(p.peek()) {
				p.pos++
			}
			part = p.src[start:p.pos]
		default:
			return nil, p.errf("invalid key character %q", string(c))
		}
		path = append(path, part)
		p.skipInlineSpace()
		if !p.eof() && p.peek() == '.' {
			p.advance()
			continue
		}
		return path, nil
	}
}

// --- table headers ------------------------------------------------------

func (p *parser) parseTableHeader() error {
	p.advance() // consume '['
	isArray := false
	if !p.eof() && p.peek() == '[' {
		isArray = true
		p.advance()
	}
	path, err := p.parseKeyPath()
	if err != nil {
		return err
	}
	if p.eof() || p.peek() != ']' {
		return p.errf("expected ']' to close table header")
	}
	p.advance()
	if isArray {
		if p.eof() || p.peek() != ']' {
			return p.errf("expected ']]' to close array-of-tables header")
		}
		p.advance()
	}
	if err := p.expectLineEnd(); err != nil {
		return err
	}

	if isArray {
		return p.openArrayTable(path)
	}
	return p.openTable(path)
}

// openTable positions the parser inside [a.b.c], creating intermediate
// tables as needed and rejecting redefinition or type conflicts.
func (p *parser) openTable(path []string) error {
	if p.explicit == nil {
		p.explicit = map[string]bool{}
	}
	key := strings.Join(path, "\x00")
	if p.explicit[key] {
		return p.errf("table [%s] is defined twice", strings.Join(path, "."))
	}
	tbl, err := p.descend(path)
	if err != nil {
		return err
	}
	p.explicit[key] = true
	p.current = tbl
	return nil
}

func (p *parser) openArrayTable(path []string) error {
	parent, err := p.descend(path[:len(path)-1])
	if err != nil {
		return err
	}
	name := path[len(path)-1]
	switch existing := parent[name].(type) {
	case nil:
		tbl := map[string]any{}
		parent[name] = []any{tbl}
		p.current = tbl
		return nil
	case []any:
		// Only extend arrays that hold tables (i.e. built by [[...]]).
		if len(existing) > 0 {
			if _, ok := existing[len(existing)-1].(map[string]any); !ok {
				return p.errf("cannot extend non-table array %q with [[%s]]", name, strings.Join(path, "."))
			}
		}
		tbl := map[string]any{}
		parent[name] = append(existing, tbl)
		p.current = tbl
		return nil
	default:
		return p.errf("key %q already holds a non-array value", name)
	}
}

// descend walks/creates intermediate tables for a header path. When the path
// crosses an array of tables it descends into the most recent element,
// matching TOML semantics.
func (p *parser) descend(path []string) (map[string]any, error) {
	cur := p.root
	for _, part := range path {
		switch next := cur[part].(type) {
		case nil:
			tbl := map[string]any{}
			cur[part] = tbl
			cur = tbl
		case map[string]any:
			cur = next
		case []any:
			if len(next) == 0 {
				return nil, p.errf("cannot descend into empty array %q", part)
			}
			last, ok := next[len(next)-1].(map[string]any)
			if !ok {
				return nil, p.errf("key %q is an array of values, not tables", part)
			}
			cur = last
		default:
			return nil, p.errf("key %q already holds a value, not a table", part)
		}
	}
	return cur, nil
}

// --- key = value --------------------------------------------------------

func (p *parser) parseKeyValue() error {
	path, err := p.parseKeyPath()
	if err != nil {
		return err
	}
	p.skipInlineSpace()
	if p.eof() || p.peek() != '=' {
		return p.errf("expected '=' after key %q", strings.Join(path, "."))
	}
	p.advance()
	p.skipInlineSpace()
	val, err := p.parseValue()
	if err != nil {
		return err
	}
	if err := p.expectLineEnd(); err != nil {
		return err
	}

	// Dotted keys create intermediate tables under the current table.
	tbl := p.current
	for _, part := range path[:len(path)-1] {
		switch next := tbl[part].(type) {
		case nil:
			sub := map[string]any{}
			tbl[part] = sub
			tbl = sub
		case map[string]any:
			tbl = next
		default:
			return p.errf("key %q already holds a value, not a table", part)
		}
	}
	leaf := path[len(path)-1]
	if _, exists := tbl[leaf]; exists {
		return p.errf("key %q is set twice", strings.Join(path, "."))
	}
	tbl[leaf] = val
	return nil
}

// --- values ---------------------------------------------------------------

func (p *parser) parseValue() (any, error) {
	if p.eof() {
		return nil, p.errf("expected a value")
	}
	switch c := p.peek(); {
	case c == '"':
		if strings.HasPrefix(p.src[p.pos:], `"""`) {
			return nil, p.errf("multi-line strings are not supported by this TOML subset")
		}
		return p.parseBasicString()
	case c == '\'':
		if strings.HasPrefix(p.src[p.pos:], `'''`) {
			return nil, p.errf("multi-line strings are not supported by this TOML subset")
		}
		return p.parseLiteralString()
	case c == '[':
		return p.parseArray()
	case c == '{':
		return nil, p.errf("inline tables are not supported by this TOML subset; use a [table] section")
	case c == 't' || c == 'f':
		return p.parseBool()
	case c == '+' || c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, p.errf("unexpected value starting with %q", string(c))
	}
}

func (p *parser) parseBasicString() (string, error) {
	p.advance() // opening quote
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errf("unterminated string")
		}
		c := p.peek()
		switch c {
		case '"':
			p.advance()
			return b.String(), nil
		case '\n':
			return "", p.errf("newline in single-line string")
		case '\\':
			p.advance()
			if p.eof() {
				return "", p.errf("unterminated escape sequence")
			}
			esc := p.advance()
			switch esc {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'u', 'U':
				n := 4
				if esc == 'U' {
					n = 8
				}
				if p.pos+n > len(p.src) {
					return "", p.errf("truncated \\%c escape", esc)
				}
				hex := p.src[p.pos : p.pos+n]
				v, err := strconv.ParseUint(hex, 16, 32)
				if err != nil {
					return "", p.errf("invalid \\%c escape %q", esc, hex)
				}
				if !utf8.ValidRune(rune(v)) {
					return "", p.errf("escape \\%c%s is not a valid Unicode scalar", esc, hex)
				}
				p.pos += n
				b.WriteRune(rune(v))
			default:
				return "", p.errf("unknown escape sequence \\%c", esc)
			}
		default:
			b.WriteByte(p.advance())
		}
	}
}

func (p *parser) parseLiteralString() (string, error) {
	p.advance() // opening quote
	start := p.pos
	for {
		if p.eof() {
			return "", p.errf("unterminated literal string")
		}
		c := p.peek()
		if c == '\'' {
			s := p.src[start:p.pos]
			p.advance()
			return s, nil
		}
		if c == '\n' {
			return "", p.errf("newline in single-line string")
		}
		p.advance()
	}
}

func (p *parser) parseBool() (any, error) {
	if strings.HasPrefix(p.src[p.pos:], "true") {
		p.pos += 4
		return true, nil
	}
	if strings.HasPrefix(p.src[p.pos:], "false") {
		p.pos += 5
		return false, nil
	}
	return nil, p.errf("unexpected value starting with %q", string(p.peek()))
}

func (p *parser) parseNumber() (any, error) {
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if c == '+' || c == '-' || c == '_' || c == '.' || c == 'e' || c == 'E' ||
			(c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		break
	}
	raw := p.src[start:p.pos]
	if raw == "" {
		return nil, p.errf("expected a number")
	}
	// Bare datetimes look like numbers followed by '-' or ':' patterns; the
	// loop above already ate the '-' digits, so detect the telltale 'T'/':'
	// that follows and refuse with a helpful message.
	if !p.eof() && (p.peek() == ':' || p.peek() == 'T' || p.peek() == 'Z') {
		return nil, p.errf("bare datetimes are not supported; quote the timestamp as an RFC 3339 string")
	}
	if strings.Count(raw, "-") > 1 && !strings.ContainsAny(raw, "eE") {
		return nil, p.errf("bare datetimes are not supported; quote the timestamp as an RFC 3339 string")
	}
	clean := strings.ReplaceAll(raw, "_", "")
	if strings.ContainsAny(clean, ".eE") {
		f, err := strconv.ParseFloat(clean, 64)
		if err != nil {
			return nil, p.errf("invalid float %q", raw)
		}
		return f, nil
	}
	i, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		return nil, p.errf("invalid integer %q", raw)
	}
	return i, nil
}

func (p *parser) parseArray() (any, error) {
	p.advance() // '['
	arr := []any{}
	for {
		p.skipBlank() // arrays may span lines and contain comments
		if p.eof() {
			return nil, p.errf("unterminated array")
		}
		if p.peek() == ']' {
			p.advance()
			return arr, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipBlank()
		if p.eof() {
			return nil, p.errf("unterminated array")
		}
		switch p.peek() {
		case ',':
			p.advance()
		case ']':
			p.advance()
			return arr, nil
		default:
			return nil, p.errf("expected ',' or ']' in array, found %q", string(p.peek()))
		}
	}
}

// IsBareKey reports whether s can be written unquoted in a TOML key
// position, so error messages can quote keys exactly as a file would.
func IsBareKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !isBareKeyChar(byte(r)) {
			return false
		}
	}
	return true
}
