package plugins

import (
	"strconv"
	"goFoxy/manager"
	"net/http"
	"goFoxy/common"
	"strings"
	"io/ioutil"
	"fmt"
)

func init() {
	pl := fileFinder{}
	pl.Name = "fileFinder"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "敏感文件扫描"
	manager.Regist(pl.Name, pl)
}

type fileFinder struct {
	manager.Plugin
}

func (this fileFinder) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this fileFinder) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this fileFinder) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func (this fileFinder) Process(flow common.Flow) {
	url := flow.GetSafeBaseURL()
	dicts := map[string]string{
		"/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
	}
	for key := range dicts {
		httpClient := http.Client{}
		resp, err := httpClient.Get(url + key)
		if err != nil {
			return
		}
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		resp.Body.Close()
		if strings.Contains(string(content), dicts[key]) {
			tmpInfo := common.Vuln{FlowID: flow.ID}
			tmpInfo.Host = flow.Host
			tmpInfo.Title = "敏感文件"
			tmpInfo.Level = "低危"
			tmpInfo.Content = fmt.Sprintf("%s 存在敏感目录或文件", url+key)
			tmpInfo.LogVulnInfo()
			break
		}
	}
}
