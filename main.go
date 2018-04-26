package main

import (
	"github.com/elazarl/goproxy"
	"log"
	"net/http"
	_ "goFoxy/plugins"
	"io/ioutil"
	"bytes"
	"goFoxy/common"
	"goFoxy/manager"
)

func main() {
	foxy := goproxy.NewProxyHttpServer()
	foxy.Verbose = true
	foxy.OnRequest().HandleConnect(goproxy.AlwaysMitm) // MITM https

	foxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// 初始化开始
			// 如果存在 POST或 GET参数，则调用 ParseForm()
			if req.ContentLength > 0 || req.URL.RawQuery != "" {
				// 复制 req.Body
				bodyBytes, _ := ioutil.ReadAll(req.Body)
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				// ParseForm()会将 req.Body.sawEOF设置为 true，调用完后需要重置 req.Body，否则进入 OnResponse后会报错
				req.ParseForm()
				// 重置req.Body的状态
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			ctx.UserData = &common.FlowContext{}
			ctx.UserData.(*common.FlowContext).RequestTime = common.GetNowTime()
			// 初始化结束
			return req, nil
		})
	foxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {

			ctx.UserData.(*common.FlowContext).ResponseTime = common.GetNowTime()
			flow := common.GenrateFlow(ctx) // 转换成 Flow结构

			// 异步执行插件
			availables := manager.GetAvailablePlugins()
			for _, plugin := range availables {
				go plugin.Process(flow)
			}
			isInsert := common.LogFlow(flow)
			if !isInsert {
				log.Printf("Flow: %s insert failed", flow.ID)
			}
			return resp
		})

	log.Fatal(http.ListenAndServe(":8080", foxy))
}
