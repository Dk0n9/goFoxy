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
	pl := weblogicFounder{}
	pl.Name = "weblogicFounder"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "weblogic console暴露检测"
	manager.Regist(pl.Name, pl)
}

type weblogicFounder struct {
	manager.Plugin
}

var weblogicHttpClient = http.Client{}

func (this weblogicFounder) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this weblogicFounder) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this weblogicFounder) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func find(flow common.Flow, url string) {
	dicts := []string{
		url + "/console",
		"http://" + strings.Replace(flow.Host, ":"+strconv.Itoa(flow.Port), "", -1) + ":7001/console",
		"http://" + strings.Replace(flow.Host, ":"+strconv.Itoa(flow.Port), "", -1) + ":8001/console",
		"http://" + strings.Replace(flow.Host, ":"+strconv.Itoa(flow.Port), "", -1) + ":9001/console",
	}

	for index := range dicts {
		tmpURL := dicts[index]
		fmt.Println(tmpURL)
		resp, err := weblogicHttpClient.Get(tmpURL)
		if err == nil {
			if resp.StatusCode == 200 {
				pContent, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(pContent), "WebLogic Server") {
					tmpInfo := common.Vuln{FlowID: flow.ID}
					tmpInfo.Host = flow.Host
					tmpInfo.Title = "Weblogic后台暴露"
					tmpInfo.Level = "低危"
					tmpInfo.Content = fmt.Sprintf("%s 可能暴露 Weblogic Console", tmpURL)
					tmpInfo.LogVulnInfo()
					break
				}
			}
		}
	}

}

func (this weblogicFounder) Process(flow common.Flow) {
	newURL := flow.GetSafeBaseURL()
	go find(flow, newURL)
}
