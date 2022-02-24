package osquery

import (
	"fmt"
	"github.com/rock-go/rock/auxlib"
	"github.com/rock-go/rock/lua"
	"path/filepath"
)

type config struct {
	name    string
	path    string
	hash    string
	flags   []string
	socket  string
	timeout int
	co      *lua.LState
}

func newConfig(L *lua.LState) *config {
	tab := L.CheckTable(1)
	cfg := &config{name:"osquery" , timeout: 10}
	tab.Range(func(key string, val lua.LValue) { cfg.NewIndex(L , key , val) })
	cfg.co = xEnv.Clone(L)
	return cfg
}

func (cfg *config) Args() []string {
	flags := []string{ cfg.path }

	for _ , item := range cfg.flags {
		flags = append(flags , "--" + item)
	}
	return  flags
}

func (cfg *config) NewIndex(L *lua.LState , key string , val lua.LValue) bool {
	switch key {
	case "name":
		cfg.name = val.String()

	case "path":
		cfg.path = val.String()

	case "socket":
		cfg.socket = val.String()

	case "hash":
		cfg.hash = val.String()

	case "timeout":
		n := lua.IsInt(val)
		if n > 0 {
			cfg.timeout = lua.IsInt(val)
		}

	case "flags":

		switch val.Type() {

		case lua.LTString:
			cfg.flags = []string{val.String()}

		case lua.LTTable:
			cfg.flags = auxlib.LTab2SS(val.(*lua.LTable))

		default:
			L.RaiseError("invalid flags")
		}

	default:
		return false

	}

	return true
}

func (cfg *config) valid() error {
	if e := auxlib.Name(cfg.name) ; e != nil {
		return e
	}

	if len(cfg.flags) == 0 {
		return fmt.Errorf("not found flags")
	}

	path , err := filepath.Abs(filepath.Clean(cfg.path))
	if err != nil {
		return err
	} else {
		cfg.path = path
	}

	socket , err := filepath.Abs(filepath.Clean(cfg.socket))
	if err != nil {
		return err
	} else {
		cfg.socket = socket
	}

	hash , err := auxlib.FileMd5(path)
	if err != nil {
		return err
	}

	if hash != cfg.hash {
		return fmt.Errorf("checksum fail got %v" , hash)
	}

	return nil
}