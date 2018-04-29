package plugins

import (
	"strconv"
	"goFoxy/manager"
	"strings"
	"fmt"
	"goFoxy/common"
)

func init() {
	pl := findPrivacy{}
	pl.Name = "findPrivacy"
	pl.Author = "dk"
	pl.Default = true
	pl.Help = "检查隐私信息泄露可能导致的其他危害"
	manager.Regist(pl.Name, pl)
}

type findPrivacy struct {
	manager.Plugin
}

func (this findPrivacy) GetPluginInfo() map[string]string {
	infoMap := make(map[string]string)
	infoMap["name"] = this.Name
	infoMap["author"] = this.Author
	infoMap["default"] = strconv.FormatBool(this.Default)
	infoMap["flag"] = strconv.FormatBool(this.Flag)
	infoMap["help"] = this.Help
	return infoMap
}

func (this findPrivacy) SetPluginFlag(flag bool) bool {
	this.Flag = flag
	return true
}

func (this findPrivacy) Toggle() {
	if this.Flag {
		this.Flag = false
	} else {
		this.Flag = true
	}
}

func checkPage(value string, body string) bool {
	if len(value) <= 4 {
		return false
	}
	if strings.Contains(body, value) {
		return true
	} else {
		urlDecodeValue, err := common.URLDecode(value)
		if err == nil {
			if strings.Contains(body, urlDecodeValue) {
				return true
			}
		}
		if common.IsB64(value) {
			b64DecodeValue := common.B64Decode(value)
			if b64DecodeValue != "" {
				if strings.Contains(body, b64DecodeValue) {
					return true
				}
			}
		}
		return false
	}
}

func checkControl(pKey, pValue, cKey, cValue string, flow common.Flow) {
	weight := common.GetContainsWeight(pValue, cValue)
	if weight > 0.4 {
		tmp := common.Vuln{FlowID: flow.ID}
		tmp.Host = flow.Host
		tmp.Title = "响应头中的 Set-Cookie可能允许被控制"
		tmp.Level = "低危"
		tmp.Content = fmt.Sprintf("参数: %s 可能可以控制 Set-Cookie中 %s的内容", pKey, cKey)
		common.LogVulnInfo(tmp)
	}
}

func (this findPrivacy) Process(flow common.Flow) {
	// 检查请求头中的cookie信息是否在响应内容的body上泄漏
	for key, value := range flow.ResponseCookies {
		if checkPage(value, flow.ResponseBody) {
			tmpInfo := common.Vuln{FlowID: flow.ID}
			tmpInfo.Host = flow.Host
			tmpInfo.Title = "Cookie内容可能在页面中可控"
			tmpInfo.Level = "低危"
			tmpInfo.Content = fmt.Sprintf("Cookie字段: %s", key)
			common.LogVulnInfo(tmpInfo)
		}
	}
	// 检查所有请求参数是否可以控制响应头的 Set-Cookie
	if len(flow.ResponseCookies) != 0 {
		for cKey, cValue := range flow.ResponseCookies {
			for pKey, pValue := range flow.Form {
				if pValue == "" {
					continue
				}

				// 字符串包含
				if strings.Contains(cValue, pValue) {
					checkControl(pKey, pValue, cKey, cValue, flow)
					continue
				}

				// 测试是否是 Base64编码
				isB64Encoded := common.IsB64(pKey)
				if isB64Encoded {
					b64Value := common.B64Decode(pValue)
					if b64Value != "" {
						if strings.Contains(cValue, b64Value) {
							checkControl(pKey, b64Value, cKey, cValue, flow)
							continue
						}
					}
				}

				// 测试是否是 URLEncode
				urlDecodeValue, err := common.URLDecode(pValue)
				if err == nil {
					if urlDecodeValue == pValue {
						continue
					} // 与原始内容不变则 contine
					if strings.Contains(cValue, urlDecodeValue) {
						checkControl(pKey, urlDecodeValue, cKey, cValue, flow)
						continue
					}
				}
			}
		}
	}

}
