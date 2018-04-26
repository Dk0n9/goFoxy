package common

import (
	"encoding/base64"
	"net/url"
	"time"
	"strings"
	"io/ioutil"
	"bytes"
	"strconv"
	"github.com/elazarl/goproxy"
	"github.com/jakehl/goid"
	"github.com/deckarep/golang-set"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/mgo.v2"
)

var Session, _ = mgo.Dial("mongodb://127.0.0.1:27017/")
var DB = Session.DB("goFoxy1")
var VulnCollect = DB.C("vuln")
var FlowCollect = DB.C("flow")

// 漏洞信息
type Vuln struct {
	FlowID     string
	Host       string
	Title      string
	Level      string
	Content    string
	CreateTime string
}

type FlowContext struct {
	RequestTime  string
	ResponseTime string
}

// 流量信息
type Flow struct {
	// UUID
	ID string
	// Request
	HttpVersion string
	RemoteAddr  string
	Scheme      string
	BasicAuth   map[string]string
	Host        string
	Port        int
	Method      string
	Path        string
	Query       map[string]string // GET 参数
	Fragment    string            // URL HASH 内容
	URL         string            // 完整URL
	Headers     map[string]string // 请求头
	Cookies     map[string]string
	Form        map[string]string // GET/POST/PUT 内容
	PostForm    map[string]string // POST 内容
	// MultipartForm *multipart.Form  // 上传内容，暂时不处理
	// Response
	ResponseStatusCode int
	ResponseHeaders    map[string]string
	ResponseCookies    map[string]string
	ResponseBody       string
	ContentLength      int64
	// Other
	CreateTime   string
	RequestTime  string
	ResponseTime string
}

// 将 ctx结构转成 Flow结构，方便读取和入库
func GenrateFlow(ctx *goproxy.ProxyCtx) Flow {
	flow := Flow{}

	// 检测生成的UUID在库中是否存在
	for {
		tmpID := goid.NewV4UUID().String() // byte to string
		num, _ := FlowCollect.Find(bson.M{"flowid": tmpID}).Count()
		if num > 0 {
			continue
		} else {
			flow.ID = tmpID
			break
		}
	}

	flow.HttpVersion = ctx.Req.Proto
	flow.RemoteAddr = ctx.Req.RemoteAddr
	flow.Scheme = ctx.Req.URL.Scheme
	flow.BasicAuth = make(map[string]string)
	username, password, ok := ctx.Req.BasicAuth()
	if ok {
		flow.BasicAuth["username"] = username
		flow.BasicAuth["password"] = password
	}
	flow.Host = ctx.Req.Host
	port, err := strconv.Atoi(ctx.Req.URL.Port())
	if err == nil {
		flow.Port = port
	}
	flow.Method = ctx.Req.Method
	flow.Path = ctx.Req.URL.Path
	// Request Query
	flow.Query = make(map[string]string)
	for key, value := range ctx.Req.URL.Query() {
		content := value[len(value)-1]
		flow.Query[key] = content
	}
	flow.Fragment = ctx.Req.URL.Fragment
	flow.URL = ctx.Req.URL.String()
	// Request Headers
	flow.Headers = make(map[string]string)
	for key, value := range ctx.Req.Header {
		content := strings.Join(value, ", ")
		flow.Headers[key] = content
	}
	// Request Cookies
	flow.Cookies = make(map[string]string)
	for _, value := range ctx.Req.Cookies() {
		flow.Cookies[value.Name] = value.Value
	}
	// Request Form
	flow.Form = make(map[string]string)
	for key, value := range ctx.Req.Form {
		content := strings.Join(value, ", ")
		flow.Form[key] = content
	}
	flow.PostForm = make(map[string]string)
	for key, value := range ctx.Req.PostForm {
		content := strings.Join(value, ", ")
		flow.PostForm[key] = content
	}

	// Response
	flow.ResponseStatusCode = ctx.Resp.StatusCode
	flow.ResponseHeaders = make(map[string]string)
	for key, value := range ctx.Resp.Header {
		content := strings.Join(value, ", ")
		flow.ResponseHeaders[key] = content
	}
	flow.ResponseCookies = make(map[string]string)
	for _, value := range ctx.Resp.Cookies() {
		flow.ResponseCookies[value.Name] = value.Value
	}
	// Read response Body && Reset
	tmpBody, err := ioutil.ReadAll(ctx.Resp.Body)
	flow.ResponseBody = string(tmpBody)
	flow.ContentLength = int64(len(tmpBody))
	ctx.Resp.Body.Close()
	body := ioutil.NopCloser(bytes.NewReader(tmpBody))
	ctx.Resp.Body = body
	ctx.Resp.ContentLength = int64(len(tmpBody))
	ctx.Resp.Header.Set("Content-Length", strconv.Itoa(len(tmpBody)))
	// Other
	flow.CreateTime = GetNowTime()
	flow.RequestTime = ctx.UserData.(*FlowContext).RequestTime
	flow.ResponseTime = ctx.UserData.(*FlowContext).ResponseTime

	return flow
}

// 将单条漏洞信息入库
func LogVulnInfo(info Vuln) bool {
	num, _ := VulnCollect.Find(bson.M{"host": info.Host, "content": info.Content}).Count()
	if num > 0 {
		return false
	}
	info.CreateTime = GetNowTime()
	err := VulnCollect.Insert(info)
	if err == nil {
		return true
	} else {
		return false
	}
}

// 将单条流量信息入库
func LogFlow(flow Flow) bool {
	err := FlowCollect.Insert(flow)
	if err == nil {
		return true
	} else {
		return false
	}
}

func IsB64(content string) bool {
	if len(content)%4 == 0 {
		return true
	} else {
		return false
	}
}

func GetNowTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func URLDecode(content string) (string, error) {
	decode, err := url.QueryUnescape(content)
	return decode, err
}

func B64Decode(content string) string {
	decodeBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return ""
	} else {
		return string(decodeBytes)
	}
}

// 使用 Jaccard系数计算文本相似度，用作判断 404页面
func SimilarText(first, second string) float64 {
	if first == second {
		return float64(1)
	}
	firstSets := mapset.NewSet()
	secondSets := mapset.NewSet()
	for i := 0; i < len(first); i += 4 {
		j := 0
		if (i + 4) > len(first) {
			j = len(first)
		} else {
			j = i + 4
		}
		firstSets.Add(first[i:j])
	}
	for i := 0; i < len(second); i += 4 {
		j := 0
		if (i + 4) > len(second) {
			j = len(second)
		} else {
			j = i + 4
		}
		secondSets.Add(second[i:j])
	}
	union := firstSets.Union(secondSets)
	intersection := firstSets.Intersect(secondSets)
	if union.Cardinality() == 0 {
		return float64(1)
	} else {
		return float64(intersection.Cardinality()) / float64(union.Cardinality())
	}
}
