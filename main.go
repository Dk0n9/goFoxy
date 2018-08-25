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
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2/bson"
)

func webIndex(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "index.html", gin.H{})
}

func getLatest(ctx *gin.Context) {
	common.WSHandler.HandleRequest(ctx.Writer, ctx.Request)
}

func getFlowDetail(ctx *gin.Context) {
	response := gin.H{
		"error":  "",
		"result": "",
	}
	flowID := ctx.Param("flowid")
	var result []interface{}
	var code int
	err := common.FlowCollect.Find(bson.M{"flowid": flowID}).One(result)
	if err != nil {
		code = 404
		response["error"] = err.Error()
	} else {
		code = 200
		response["result"] = result
	}
	ctx.JSON(code, response)
}

func getFlowVulns(ctx *gin.Context) {
	response := gin.H{
		"error":  "",
		"result": "",
	}
	flowID := ctx.Param("flowid")
	var result []interface{}
	var code int
	err := common.VulnCollect.Find(bson.M{"flowid": flowID}).All(result)
	if err != nil {
		code = 404
		response["error"] = err.Error()
	} else {
		code = 200
		response["result"] = result
	}
	ctx.JSON(code, response)
}

func StartWeb(addr ...string) {
	var address string
	if len(addr) == 0 {
		address = "localhost:35277"
	} else {
		address = addr[0]
	}
	router := gin.Default()
	// set route
	router.LoadHTMLGlob("templates/*")
	router.GET("/", webIndex)
	router.GET("/latest", getLatest)
	router.GET("/flow/:flowid", getFlowDetail)
	router.GET("/vuln/:flowid", getFlowVulns)

	router.Run(address) // listen and serve on 0.0.0.0:35277
}

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
			ctx.UserData.(*common.FlowContext).FlowID = common.GenrateFlowID()
			ctx.UserData.(*common.FlowContext).RequestTime = common.GetNowTime()
			// End
			// Broadcast
			tmpFlow := common.GenrateFlow(ctx)
			tmpFlow.Broadcast("add")
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
			flow.Broadcast("update")
			isInsert := flow.LogFlow()
			if !isInsert {
				log.Printf("URL: %s insert failed", flow.URL)
			}
			return resp
		})

	go StartWeb("0.0.0.0:35277") // start the web server
	log.Fatal(http.ListenAndServe(":8080", foxy))
}
