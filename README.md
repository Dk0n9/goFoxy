# goFoxy - An HTTP(S) Proxy And Passive Vuln Scanner implemented by golang

## 环境配置
代理需要依赖 mongodb数据库来存储流量信息和漏洞信息，在 `./common/common.go`中配置你的数据库连接

## 运行
```
go build main.go
./main
```

## 插件编写的注意事项
* 如果需要取得当前请求的根目录url（如：hxxp://example.com:999/），最好使用 `flow.GetSafeBaseURL()`函数获取，函数内部已做好了一些兼容性处理

## 已知问题
* 在 `MITM`模式下（默认开启），不支持 websocket(secure)的处理
