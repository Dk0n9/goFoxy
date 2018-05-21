package plugins

import (
	"strconv"
	"goFoxy/manager"
	"net/http"
	"strings"
	"fmt"
	"goFoxy/common"
)

func init() {
	pl := redirect{}
	pl.Name = "openURLRedirectDetect"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "检测可能存在的 url跳转"
	manager.Regist(pl.Name, pl)
}

type redirect struct {
	manager.Plugin
}

//var waitGroup sync.WaitGroup
var RedirectPayloads = map[string]string{
	"//{target}/%2f..":                  "",
	"https://{target}/%2f..":            "",
	"https://{target}":                  "",
	"&%0d%0a1Location:https://{target}": "",
	"/.{target}":                        "",
	"https://;@{target}":                "",
}
var globalFlow common.Flow

func (this redirect) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this redirect) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this redirect) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func checkRedirectVulnerable(req *http.Request, via []*http.Request) error {
	for _, originReq := range via[len(via)-1:] { // 每次只取 via的最后一个
		if strings.HasSuffix(originReq.URL.Host, req.URL.Host) && originReq.URL.Host != req.URL.Host {
			tmpInfo := common.Vuln{FlowID: globalFlow.ID}
			tmpInfo.Host = globalFlow.Host
			tmpInfo.Title = "url跳转漏洞"
			tmpInfo.Level = "低危"
			tmpInfo.Content = fmt.Sprintf("%s 可能存在 url跳转漏洞", req.URL.String())
			tmpInfo.LogVulnInfo()
		}
	}
	return nil
}

func testRedirect(url string) {
	httpClient := http.Client{CheckRedirect: checkRedirectVulnerable}
	httpClient.Get(url)
}

func (this redirect) Process(flow common.Flow) {
	flowDomain := flow.ID + "." + flow.Host
	globalFlow = flow
	for payload := range RedirectPayloads {
		newURL := flow.Scheme + "://" + flow.Host + "/" + strings.Replace(payload, "{target}", flowDomain, 1)
		go testRedirect(newURL) // 并发执行 Redirect测试
	}
}
