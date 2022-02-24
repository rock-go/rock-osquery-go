# osquery

```text
    作者: edunx
    企业: eastmoney.com
    邮箱: dym518518@gmail.com
```

- [github.com/rock-go/rock-osquery-go](https://github.com/rock-go/rock-osquery-go)

## rock.osquery
- [rock.osquery{name , path , hash , flags , socket , timeout} userdata](#)
- name: 进程名称
- path: osquery 可执行文件路径
- hash: osquery 的checksum
- flags: osquery 配置参数 数组
- socket: socket api 路径
- timeout: 操作超时时间

#### 内部方法
- [userdata.query(sql) reply](结果)

```lua
    local client = rock.osquery{
        name = "client",
        hash = "0e35ab6b34f3d06aec048db77756b7af",
        path = "share/software/osquery/bin/osqueryd",
        socket = "share/shell.em",
        flags = {
            "disable_extensions=false",
            "database_path=share/osquery.db",
            "extensions_socket=share/shell.em",
        }
    }

    --启动
    client.start()

    --设置为默认
    client.default()

    local r = client.query("select * from last") --linux
```

## rock.query
- [rock.query(sql) reply](#内部接口)
- 注意: 需要先client.default()设置默认client 才能全局调用

## 内部接口
- 类型: userdata
- [reply.ok](#)
- [reply.msg](#)
- [reply.raw](#)
- [reply.code](#)
- [reply.uuid](#)
- [reply.warp](#) &nbsp;错误信息
- [reply.ipairs(function)](#) &nbsp; 轮询回调
```lua
    local rx = rock.query("select * from last")
    print(rx.ok)
    print(rx.msg)
    print(rx.raw)
    print(rx.code)
    print(rx.uuid)
    print(rx.warp)
    
    rx.ipairs(function(row)
        print(row.username)
        print(row.tty)
        print(row.pid)
        print(row.type)
        print(row.type_name)
        print(row.time)
        print(row.host)
    end)
```