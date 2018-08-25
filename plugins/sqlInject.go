package plugins

import (
	"strconv"
	"goFoxy/manager"
	"net/http"
	"encoding/json"
	"math/rand"
	"fmt"
	"strings"
	"log"
	"bytes"
	"time"
	"reflect"
	"goFoxy/common"
)

func init() {
	pl := sqlInject{}
	pl.Name = "Sql注入插件"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "使用 Sqlmap API检查带参数请求是否存在 SQL注入"
	manager.Regist(pl.Name, pl)
}

var sqlmapServers = []string{"127.0.0.1:8775"}
var history = make(map[string]string)

type sqlInject struct {
	manager.Plugin
}

type taskParams struct {
	Url     string `json:"url"`
	Method  string `json:"method"`
	Cookie  string `json:"cookie"`
	Headers string `json:"headers"`
	Data    string `json:"data"`
}

func (this sqlInject) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this sqlInject) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this sqlInject) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

// Content-Type whitelist
func isInWhiteList(content string) bool {
	whiteList := []string{"text/asp", "text/html", "text/plain", "application/json"}
	for index := range whiteList {
		if strings.Contains(whiteList[index], content) {
			return true
		}
	}
	return false
}

// Creat task
// request /task/new, return taskid
func createTask(server string) string {
	if len(sqlmapServers) == 0 {
		return ""
	}
	httpClient := http.Client{}
	resp, err := httpClient.Get(fmt.Sprintf("http://%s/task/new", server))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	result := struct {
		Taskid  string `json:"taskid"`
		Success bool   `json:"success"`
	}{}
	err = decoder.Decode(&result)

	if err != nil {
		return ""
	} else {
		return result.Taskid
	}
	return ""
}

// Set target and start task
// request /scan/<taskid>/start
func startTask(server string, taskID string, info taskParams) bool {
	url := fmt.Sprintf("http://%s/scan/%s/start", server, taskID)
	httpClient := http.Client{}
	jsonString, err := json.Marshal(info)
	if err != nil {
		return false
	}
	postData := bytes.NewReader(jsonString)
	resp, err := httpClient.Post(url, "application/json", postData)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	result := struct {
		Engineid int  `json:"engineid"`
		Success  bool `json:"success"`
	}{}
	err = decoder.Decode(&result)
	if err != nil {
		return false
	} else {
		return result.Success
	}
}

// Task monitor and fetch task result
// /scan/<taskid>/status，/scan/<taskid>/data
func taskMonitor(server string, flow common.Flow, taskID string) {
	httpClient := http.Client{}
	statusURL := fmt.Sprintf("http://%s/scan/%s/status", server, taskID)
	resultURL := fmt.Sprintf("http://%s/scan/%s/data", server, taskID)
	for {
		statusResp, err := httpClient.Get(statusURL)
		if err != nil {
			return
		}
		decoder := json.NewDecoder(statusResp.Body)
		statusResult := struct {
			Status     string `json:"status"`
			Returncode int    `json:"returncode"`
			Success    bool   `json:"success"`
		}{}
		err = decoder.Decode(&statusResult)
		statusResp.Body.Close()
		// wait for task finish
		if statusResult.Status != "terminated" {
			time.Sleep(5 * time.Second)
			continue
		}

		dataResp, err := httpClient.Get(resultURL)
		if err != nil {
			return
		}
		decoder = json.NewDecoder(dataResp.Body)
		result := struct {
			Success bool                     `json:"success"`
			Error   []string                 `json:"error"`
			Data    []map[string]interface{} `json:"data"`
		}{}
		err = decoder.Decode(&result)
		dataResp.Body.Close()
		if len(result.Data) > 0 {
			// Shit
			for index := range result.Data {
				tmpType := make([]interface{}, 0)
				if reflect.TypeOf(result.Data[index]["value"]) == reflect.TypeOf(tmpType) {
					sqlmapValues := result.Data[index]["value"].([]interface{})
					for vIndex := range sqlmapValues {
						param := sqlmapValues[vIndex].(map[string]interface{})["parameter"].(string)
						injectTypes := sqlmapValues[vIndex].(map[string]interface{})["data"].(map[string]interface{})
						for _, iValue := range injectTypes {
							injectTitle := iValue.(map[string]interface{})["title"].(string)
							injectPayload := iValue.(map[string]interface{})["payload"].(string)
							info := common.Vuln{FlowID: flow.ID}
							info.Host = flow.Host
							info.Title = "SQL注入漏洞"
							info.Level = "高危"
							info.Content = fmt.Sprintf("%s 参数：%s，注入类型：%s，注入Payload：%s",
								flow.URL, param, injectTitle, injectPayload)
							// Insert to database
							info.LogVulnInfo()
							break
						}
					}
				}
			}
			// finish.
			return
		}
		// no result，finish
		return
	}
}

func (this sqlInject) Process(flow common.Flow) {
	// Only detect http/https protocol's flow
	if flow.Scheme != "http" && flow.Scheme != "https" {
		return
	}
	// If target in history
	if _, ok := history[flow.URL]; ok {
		return
	}

	// Empty parameter
	if len(flow.Form) == 0 {
		return
	}
	// check Content-Type
	responseType := flow.ResponseHeaders["Content-Type"]
	checked := isInWhiteList(responseType)
	if !checked {
		return
	}
	// Construction sqlmapapi task parameters
	param := taskParams{Url: flow.URL}
	param.Method = flow.Method
	tmpStr := ""
	if len(flow.Cookies) > 0 {
		for key, value := range flow.Cookies {
			tmpStr += key + "=" + value + ";"
		}
	}
	param.Cookie = tmpStr
	if len(flow.PostForm) > 0 {
		tmpStr = ""
		for key, value := range flow.PostForm {
			tmpStr += key + "=" + value + "&"
		}
		param.Data = tmpStr[0 : len(tmpStr)-1]
	} else {
		param.Data = ""
	}
	headerStr := ""
	for key, value := range flow.Headers {
		headerStr += key + ": " + value + "\n"
	}
	param.Headers = headerStr
	index := rand.Intn(len(sqlmapServers)) // random choice sqlmapapi node
	taskID := createTask(sqlmapServers[index])
	// add target to history
	history[flow.URL] = ""

	result := startTask(sqlmapServers[index], taskID, param)
	if !result {
		log.Println(fmt.Sprintf("Start sqlmap task failed! taskid: %s flowid: %s", taskID, flow.ID))
	} else {
		taskMonitor(sqlmapServers[index], flow, taskID)
	}
}
