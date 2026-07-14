// Ordered JSON encoding. Byte-stable tokens require byte-stable claim
// serialization, and encoding/json randomizes nothing but offers no key
// ordering for maps — so personad builds every JSON object it signs (and
// every JSON document it serves) as an explicit ordered sequence of pairs.
package jose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Obj is a JSON object with a fixed, caller-controlled key order.
type Obj struct {
	keys []string
	vals map[string]any
}

// NewObj returns an empty ordered object.
func NewObj() *Obj {
	return &Obj{vals: map[string]any{}}
}

// Set appends key with value, or overwrites the value in place (keeping the
// original position) when key was already set.
func (o *Obj) Set(key string, value any) *Obj {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = value
	return o
}

// SetSorted inserts every entry of m in ascending key order. Used for
// persona-defined claims so that config map iteration order never leaks
// into token bytes.
func (o *Obj) SetSorted(m map[string]any) *Obj {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o.Set(k, m[k])
	}
	return o
}

// Get returns the value for key and whether it is present.
func (o *Obj) Get(key string) (any, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// Len returns the number of entries.
func (o *Obj) Len() int { return len(o.keys) }

// MarshalJSON writes the object with keys in insertion order. Values are
// encoded by encoding/json (nested *Obj values recurse through this method).
func (o *Obj) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, fmt.Errorf("claim %q: %w", k, err)
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Encode returns the compact JSON bytes, panicking only on programmer error
// (unencodable value types are rejected by config validation first).
func (o *Obj) Encode() []byte {
	b, err := o.MarshalJSON()
	if err != nil {
		panic("jose: unencodable object: " + err.Error())
	}
	return b
}

// EncodeIndent returns pretty-printed JSON with the same key order, for
// human-facing CLI output (discovery, JWKS, claims).
func (o *Obj) EncodeIndent() []byte {
	var out bytes.Buffer
	if err := json.Indent(&out, o.Encode(), "", "  "); err != nil {
		panic("jose: reindent failed: " + err.Error())
	}
	out.WriteByte('\n')
	return out.Bytes()
}
