package osquery

import (
	"context"
	"fmt"
	"github.com/osquery/osquery-go"
	"github.com/rock-go/rock/lua"
	"gopkg.in/tomb.v2"
	"os/exec"
	"reflect"
	"sync"
	"time"
)

var typeof = reflect.TypeOf((*osq)(nil)).String()

var client *osq

type osq struct {
	lua.Super
	cfg  *config
	tom  *tomb.Tomb
	cmd  *exec.Cmd
	mux  sync.Mutex
	ctx  context.Context
	kill context.CancelFunc
	cli  *osquery.ExtensionManagerClient
}

func newOsq(cfg *config) *osq {
	o := &osq{cfg: cfg}
	o.V(lua.INIT , typeof)
	return o
}

func (o *osq) Name() string {
	return o.cfg.name
}

func (o *osq) Type() string {
	return typeof
}

func (o *osq) Code() string {
	return o.cfg.co.CodeVM()
}

func (o *osq) Start() error {
	o.tom = new(tomb.Tomb)

	if e := o.forkExec(); e != nil {
		return e
	}

	if e := o.connect(); e != nil {
		return e
	}

	o.ctx , o.kill = context.WithCancel(context.TODO())
	return nil
}

func (o *osq) Close() error {
	if o.cmd.Process != nil {
		o.cmd.Process.Kill()
	}

	if client.Name() == o.Name() {
		client = nil
	}

	o.kill()
	o.tom.Kill(fmt.Errorf("osquery kill"))

	return nil
}

func (o *osq) forkExec() error {
	o.mux.Lock()
	defer o.mux.Unlock()

	cmd := &exec.Cmd{
		Path: o.cfg.path ,
		Args: o.cfg.Args() ,
		SysProcAttr: newSysProcAttr(),
	}

	if e := cmd.Start(); e != nil {
		return e
	}

	o.tom.Go(cmd.Wait)
	o.cmd = cmd
	return nil
}

func (o *osq) connect() error {
	timeout := time.Duration(o.cfg.timeout) * time.Second
	cli , err := osquery.NewClient(o.cfg.socket , timeout)
	if err != nil {
		return err
	}
	o.cli = cli
	return nil
}