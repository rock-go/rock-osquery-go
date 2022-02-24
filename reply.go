package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/rock-go/rock/json"
	"github.com/rock-go/rock/lua"
)

type reply struct {
	Status *osquery.ExtensionStatus
	Body   []map[string]string
	Err    error
}

func newReply(r *osquery.ExtensionResponse, e error) reply {
	if r == nil {
		return reply{Err: e}
	}

	return reply{
		Status: r.Status,
		Body:   r.Response,
		Err:    e,
	}
}

func (r reply) String() string                         { return fmt.Sprintf("%p", &r) }
func (r reply) Type() lua.LValueType                   { return lua.LTObject }
func (r reply) AssertFloat64() (float64, bool)         { return 0, false }
func (r reply) AssertString() (string, bool)           { return "", false }
func (r reply) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (r reply) Peek() lua.LValue                       { return r }

func (r reply) Meta(L *lua.LState, key lua.LValue) lua.LValue {
	n, ok := key.AssertFloat64()
	if !ok {
		return lua.LNil
	}

	idx := int(n)
	if idx >= len(r.Body) {
		return lua.LNil
	}

	return row(r.Body[idx])
}

func (r reply) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "ok":
		return lua.LBool(r.ok())

	case "msg":
		if r.ok() {
			return lua.S2L(r.Status.Message)
		}
	case "raw":
		if r.ok() {
			return lua.B2L(r.raw())
		}

	case "code":
		if r.ok() {
			return lua.LInt(r.Status.Code)
		}

	case "uuid":
		if r.ok() {
			return lua.LNumber(r.Status.UUID)
		}

	case "warp":
		if !r.ok() {
			return lua.S2L(r.Err.Error())
		}

	case "ipairs":
		if r.ok() {
			return L.NewFunction(r.ipairs)
		}

	}

	return lua.LNil
}

func (r *reply) ok() bool {
	if r.Err == nil {
		return true
	}
	return false
}

func (r *reply) ipairs(L *lua.LState) int {
	if !r.ok() {
		return 0
	}

	fn := L.IsFunc(1)
	if fn == nil {
		return 0
	}

	n := len(r.Body)
	if n == 0 {
		return 0
	}

	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	cp := xEnv.P(fn)

	for i := 0; i < n; i++ {
		err := co.CallByParam(cp, lua.LNumber(i), row(r.Body[i]))
		if err != nil {
			L.Push(lua.S2L(err.Error()))
			return 1
		}

		if co.IsTrue(-1) {
			return 0
		}

		co.SetTop(0)
	}

	return 0
}

func (r *reply) raw() []byte {
	n := len(r.Body)
	if n == 0 {
		return []byte("[]")
	}

	buffer := json.NewEncoder()
	buffer.Arr("")
	for i := 0; i < n; i++ {
		buffer.Tab("")
		for key, val := range r.Body[i] {
			buffer.KV(key, val)
		}
		buffer.End("},")
	}
	buffer.End("]")

	return buffer.Bytes()
}
