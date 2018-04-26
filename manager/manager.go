// Plugins Manager

package manager

import "goFoxy/common"

var allPlugins map[string]PluginInterface
var availablePlugins map[string]PluginInterface

// 插件辅助信息
type Plugin struct {
	Name    string // 插件名称
	Author  string // 插件作者
	Default bool   // 插件默认开关
	Flag    bool   // 插件开关
	Help    string // 插件帮助
}

type PluginInterface interface {
	GetPluginInfo() map[string]string // 获取插件信息
	SetPluginFlag(flag bool) bool     // 设置插件开关
	Toggle()                          // 切换插件开关
	Process(flow common.Flow)         // 处理流量
}

func init() {
	allPlugins = make(map[string]PluginInterface)
	availablePlugins = make(map[string]PluginInterface)
}

func Regist(name string, plugin PluginInterface) {
	allPlugins[name] = plugin
	info := plugin.GetPluginInfo()
	if info["default"] == "true" {
		plugin.SetPluginFlag(true)
		availablePlugins[name] = plugin // 如果插件默认为开，则一并加入已激活插件列表
	} else {
		plugin.SetPluginFlag(false)
	}
}

func GetAllPluginsName() []string {
	pluginsNumber := len(allPlugins)
	nameArray := make([]string, pluginsNumber)
	for name := range allPlugins {
		nameArray = append(nameArray, name)
	}
	return nameArray
}

func GetAvailablePluginsName() []string {
	pluginsNumber := len(availablePlugins)
	nameArray := make([]string, pluginsNumber)
	for name := range availablePlugins {
		nameArray = append(nameArray, name)
	}
	return nameArray
}

func GetAvailablePlugins() map[string]PluginInterface {
	return availablePlugins
}

func GetPluginInfo(name string) map[string]string {
	plugin := allPlugins[name]
	return plugin.GetPluginInfo()
}

func SetPluginFlag(name string, flag bool) bool {
	/*
	启用/禁用插件
	 */
	plugin, exist := allPlugins[name]
	if exist {
		plugin.SetPluginFlag(flag)
		if flag { // 启用插件并且添加到已激活插件列表中
			_, AvailableExist := availablePlugins[name]
			if !AvailableExist {
				availablePlugins[name] = allPlugins[name]
			}
		} else { // 禁用插件并且从已激活插件列表中移除
			_, AvailableExist := availablePlugins[name]
			if AvailableExist {
				delete(availablePlugins, name)
			}
		}
		return true
	} else {
		return false
	}
}
