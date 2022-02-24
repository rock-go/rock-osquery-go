package osquery

import (
	"github.com/rock-go/rock/lua"
)

func (o *osq) queryL(L *lua.LState) int {
	if o.cli == nil {
		return 0
	}

	r , e := o.cli.Query(L.IsString(1))
	L.Push(newReply(r , e))
	return 1
}

func (o *osq) startL(L *lua.LState) int {
	if o.Code() != L.CodeVM() {
		L.RaiseError("invalid CodeVM")
		return 0
	}

	xEnv.Start(o , func(err error) {
		L.RaiseError("%v" , err)
	})
	return 0
}

func (o *osq) defL(L *lua.LState) int {
	if client == nil {
		client = o
	}
	return 0
}

func (o *osq) Index(L *lua.LState , key string) lua.LValue {
	switch key {
	case "query":
		return L.NewFunction(o.queryL)

	case "start":
		return L.NewFunction(o.startL)

	case "default":
		return L.NewFunction(o.defL)
	}
	return lua.LNil
}