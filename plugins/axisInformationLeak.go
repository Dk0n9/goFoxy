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
	pl := axisInformationLeak{}
	pl.Name = "axisInformationLeak"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "Axis信息泄漏"
	manager.Regist(pl.Name, pl)
}

type axisInformationLeak struct {
	manager.Plugin
}

func (this axisInformationLeak) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this axisInformationLeak) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this axisInformationLeak) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func (this axisInformationLeak) Process(flow common.Flow) {
	url := flow.GetSafeBaseURL()
	dicts := []string{
		url + "/axis2-web/HappyAxis.jsp",
		url + "/axis2/axis2-web/HappyAxis.jsp",
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
		if strings.Contains(string(content), "Axis2 Happiness Page") {
			tmpInfo := common.Vuln{FlowID: flow.ID}
			tmpInfo.Host = flow.Host
			tmpInfo.Title = "Axis2信息泄漏"
			tmpInfo.Level = "低危"
			tmpInfo.Content = fmt.Sprintf("%s 存在Axis2信息泄漏漏洞", dicts[index])
			tmpInfo.LogVulnInfo()
			break
		}
	}
}
