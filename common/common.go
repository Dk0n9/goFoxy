package common

import (
	"encoding/base64"
	"net/url"
	"time"
	"strings"
	"io/ioutil"
	"bytes"
	"strconv"
	"github.com/selslack/goproxy"
	"github.com/deckarep/golang-set"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/mgo.v2"
	"gopkg.in/olahol/melody.v1"
	"encoding/json"
	"github.com/jakehl/goid"
)

var WSHandler = melody.New()
var Session = &mgo.Session{}
var DB = &mgo.Database{}
var VulnCollect = &mgo.Collection{}
var FlowCollect = &mgo.Collection{}

func init() {
	Session, err := mgo.Dial("mongodb://192.168.116.128:27017/")
	// panic error
	if err != nil {
		panic("Database connection failed: " + err.Error())
	}
	DB = Session.DB("goFoxy")
	VulnCollect = DB.C("vuln")
	FlowCollect = DB.C("flow")
}

// 漏洞信息
type Vuln struct {
	FlowID     string `json:"flowid"`
	Host       string `json:"host"`
	Title      string `json:"title"`
	Level      string `json:"level"`
	Content    string `json:"content"`
	CreateTime int64  `json:"createtime"`
}

type FlowContext struct {
	FlowID       string
	RequestTime  int64
	ResponseTime int64
}

// 流量信息
type Flow struct {
	// UUID
	ID      string `json:"id"`
	Session int64  `json:"session"`
	// Request
	HttpVersion   string            `json:"httpVersion"` // e.g. "HTTP/1.0"
	RemoteAddr    string            `json:"remoteAddr"`
	Scheme        string            `json:"scheme"` // e.g. "http"
	BasicAuth     map[string]string `json:"basicAuth"`
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         map[string]string `json:"query"`    // GET 参数
	Fragment      string            `json:"fragment"` // URL HASH 内容
	URL           string            `json:"url"`      // uri
	Headers       map[string]string `json:"headers"`
	Cookies       map[string]string `json:"cookies"`
	Form          map[string]string `json:"form"`     // GET/POST/PUT 内容
	PostForm      map[string]string `json:"postform"` // POST 内容
	ContentLength int64             `json:"contentLength"`
	// MultipartForm *multipart.Form  // 上传内容，暂时不处理
	// Response
	ResponseHttpVersion   string            `json:"responseHttpVersion"` // e.g. "HTTP/1.0"
	ResponseStatus        string            `json:"responseStatus"`      // e.g. "200 OK"
	ResponseStatusCode    int               `json:"responseStatusCode"`  // e.g. 200
	ResponseHeaders       map[string]string `json:"responseHeaders"`
	ResponseCookies       map[string]string `json:"responseCookies"`
	ResponseBody          string            `json:"responseBody"`
	ResponseContentLength int64             `json:"responseContentLength"`
	// Other
	CreateTime   int64 `json:"createTime"`
	RequestTime  int64 `json:"requestTime"`
	ResponseTime int64 `json:"responseTime"`
}

// 检测生成的UUID在库中是否存在
func GenrateFlowID() string {
	for {
		tmpID := goid.NewV4UUID().String() // byte to string
		num, _ := FlowCollect.Find(bson.M{"flowid": tmpID}).Count()
		if num > 0 {
			continue
		} else {
			return tmpID
		}
	}
}

// 将 ctx结构转成 Flow结构，方便读取和入库
func GenrateFlow(ctx *goproxy.ProxyCtx) Flow {
	flow := Flow{}

	// ============ Request ============
	flow.ID = ctx.UserData.(*FlowContext).FlowID
	flow.Session = ctx.Session
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
	// Default 80
	if port == 0 {
		flow.Port = 80
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
	flow.ContentLength = ctx.Req.ContentLength

	flow.RequestTime = ctx.UserData.(*FlowContext).RequestTime

	// ============ Response ============
	// check Empty Response
	if ctx.Resp != nil {
		flow.ResponseStatusCode = ctx.Resp.StatusCode
		flow.ResponseStatus = ctx.Resp.Status
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
		tmpBody, _ := ioutil.ReadAll(ctx.Resp.Body)
		flow.ResponseBody = string(tmpBody)
		flow.ResponseContentLength = int64(len(tmpBody))
		ctx.Resp.Body.Close()
		body := ioutil.NopCloser(bytes.NewReader(tmpBody))
		ctx.Resp.Body = body
		ctx.Resp.ContentLength = int64(len(tmpBody))
		ctx.Resp.Header.Set("Content-Length", strconv.Itoa(len(tmpBody)))

		flow.ResponseTime = ctx.UserData.(*FlowContext).ResponseTime
	}
	// Other
	flow.CreateTime = GetNowTime()

	return flow
}

// Prevent other protocol, such as (ws/wss)
func (this Flow) GetSafeBaseURL() string {
	scheme := this.Scheme
	if scheme == "ws" {
		scheme = "http"
	}
	if scheme == "wss" {
		scheme = "https"
	} else {
		scheme = "http" // default http
	}
	return scheme + "://" + this.Host + ":" + strconv.Itoa(this.Port)
}

func (this Vuln) Broadcast() {
	jsonInfo, err := json.Marshal(struct {
		Type string `json:"type"`
		Cmd  string `json:"cmd"`
		Flow Vuln   `json:"data"`
	}{
		Type: "vuln",
		Cmd:  "add",
		Flow: this,
	})
	if err == nil {
		WSHandler.Broadcast(jsonInfo)
	}
}

// insert to database
func (this Vuln) LogVulnInfo() bool {
	num, _ := VulnCollect.Find(bson.M{"host": this.Host, "content": this.Content}).Count()
	if num > 0 {
		return false
	}
	this.CreateTime = GetNowTime()
	this.Broadcast()
	err := VulnCollect.Insert(this)
	if err == nil {
		return true
	} else {
		return false
	}
}

func (this Flow) Broadcast(mode string) {
	jsonInfo, err := json.Marshal(struct {
		Type string `json:"type"`
		Cmd  string `json:"cmd"`
		Flow Flow   `json:"data"`
	}{
		Type: "vuln",
		Cmd:  mode,
		Flow: this,
	})
	if err == nil {
		WSHandler.Broadcast(jsonInfo)
	}
}

// insert to database
func (this Flow) LogFlow() bool {
	err := FlowCollect.Insert(this)
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

func GetNowTime() int64 {
	return time.Now().Unix()
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

// 简单计算字符串A在字符串B中的占比
func GetContainsWeight(keyword, content string) float32 {
	kLength := len(keyword)
	cLength := len(content)
	if kLength > cLength {
		return 0.0
	}
	weight := float32(1 / (cLength / kLength))
	return weight
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
