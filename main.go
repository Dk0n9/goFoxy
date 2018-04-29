package main

import (
	"github.com/selslack/goproxy"
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
	foxy.OnRequest().HandleConnect(goproxy.AlwaysMitm) // MITM

	foxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Start
			// Call ParseForm() if have parameters
			if req.ContentLength > 0 || req.URL.RawQuery != "" {
				// Copy req.Body
				bodyBytes, _ := ioutil.ReadAll(req.Body)
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
				// ParseForm() will set req.Body.sawEOF to true
				// and need to reset the req.Body after the ParseForm()
				req.ParseForm()
				// Reset req.Body
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			ctx.UserData = &common.FlowContext{}
			ctx.UserData.(*common.FlowContext).RequestTime = common.GetNowTime()
			// End
			return req, nil
		})
	foxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {

			ctx.UserData.(*common.FlowContext).ResponseTime = common.GetNowTime()
			flow := common.GenrateFlow(ctx) // 转换成 Flow结构

			// Execute plugins
			availables := manager.GetAvailablePlugins()
			for _, plugin := range availables {
				go plugin.Process(flow)
			}
			// Insert to database
			isInsert := common.LogFlow(flow)
			if !isInsert {
				log.Printf("URL: %s insert failed", flow.URL)
			}
			return resp
		})

	log.Fatal(http.ListenAndServe(":8080", foxy))
}
