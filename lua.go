package osquery

import (
	"fmt"
	"github.com/rock-go/rock/lua"
	"github.com/rock-go/rock/xbase"
)

var (
	xEnv *xbase.EnvT
)

/*
	local cli = rock.osquery{
		name  = "client",
		path  = "share/software/osqueryd",
		flags = {"a=123" , "bb=456" , "xx==789"}
	}
	cli.start()

	local rx = cli.query("select * from aa")
 */

func constructor(L *lua.LState) int {
	cfg  := newConfig(L)
	proc := L.NewProc(cfg.name , typeof)
	if proc.IsNil() {
		proc.Set(newOsq(cfg))
	} else {
		o := proc.Data.(*osq)
		xEnv.Free(o.cfg.co)
		o.cfg = cfg
	}

	L.Push(proc)
	return 1
}

func queryL(L *lua.LState) int {
	if client == nil {
		L.Push(newReply(nil , fmt.Errorf("not found osquery client")))
		return 1
	}

	r , e := client.cli.Query(L.IsString(1))
	L.Push(newReply(r , e))
	return 1
}

func LuaInjectApi(env *xbase.EnvT) {
	xEnv = env
	env.Set("osquery", lua.NewFunction(constructor))
	env.Set("query"  , lua.NewFunction(queryL))
}
