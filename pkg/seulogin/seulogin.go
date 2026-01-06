package seulogin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	loggerPkg "github.com/nerdneilsfield/seulogin/pkg/logger"
	"go.uber.org/zap"
)

var logger = loggerPkg.GetLogger()

const (
	BaseURLAddr = "https://w.seu.edu.cn:802"
	BaseURLIP   = "https://10.80.128.2:802"
	LoginPath   = "/eportal/"

	loginCallback = "dr1004"
	loginMethod   = "1"
	loginJsVer    = "3.3.3"
	loginMac      = "000000000000"
)

func Check(err error) {
	if err != nil {
		// log.Println(err)
		logger.Error(err.Error())
	}
}

func BuildLoginForm(userName string, userPass string, uaddress string) url.Values {
	logger.Debug("Build login form....")
	form := url.Values{}
	form.Add("callback", loginCallback)
	form.Add("login_method", loginMethod)
	form.Add("user_account", ",0,"+userName)
	form.Add("user_password", userPass)
	form.Add("wlan_user_ip", uaddress)
	form.Add("wlan_user_ipv6", "")
	form.Add("wlan_user_mac", loginMac)
	form.Add("wlan_ac_ip", "")
	form.Add("wlan_ac_name", "")
	form.Add("jsVersion", loginJsVer)
	form.Add("v", strconv.FormatInt(time.Now().UnixNano()%1000, 10))
	return form
}

func DoLogin(form url.Values, useIp bool) (bool, string) {
	logger.Debug("Do login....")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	var loginFullUrl string
	if useIp {
		loginFullUrl = BaseURLIP + LoginPath
	} else {
		loginFullUrl = BaseURLAddr + LoginPath
	}

	loginURL := loginFullUrl + "?" + form.Encode()
	req, err := http.NewRequest("GET", loginURL, nil)
	Check(err)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Referer", BaseURLAddr+"/")

	resp, err := client.Do(req)
	Check(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	Check(err)

	success, msg := parseLoginResponse(body)
	if success {
		logger.Info("Login success!", zap.String("User", form.Get("user_account")), zap.String("IP", form.Get("wlan_user_ip")), zap.String("time", time.Now().Format("2006-01-02 15:04:05")))
		return true, "Login success!"
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, body, "", "\t")
	Check(err)
	if msg == "" {
		logger.Error("Login failed! ", zap.String("body", prettyJSON.String()))
		return false, "Login failed! " + prettyJSON.String()
	}
	logger.Error("Login failed! ", zap.String("msg", msg))
	return false, "Login failed! " + msg
}

func LoginToSeulogin(userName string, userPass string, userIp string, useIp bool) (bool, string) {
	form := BuildLoginForm(userName, userPass, userIp)
	return DoLogin(form, useIp)
}

func parseLoginResponse(body []byte) (bool, string) {
	raw := bytes.TrimSpace(body)
	callbackPrefix := []byte(loginCallback + "(")
	if bytes.HasPrefix(raw, callbackPrefix) {
		raw = bytes.TrimPrefix(raw, callbackPrefix)
		if len(raw) > 0 && raw[len(raw)-1] == ')' {
			raw = raw[:len(raw)-1]
		}
	}
	raw = bytes.TrimSuffix(raw, []byte(";"))

	if value, err := jsonparser.GetString(raw, "msg"); err == nil && value != "" {
		if isLoginSuccess(raw) {
			return true, value
		}
		return false, value
	}

	if isLoginSuccess(raw) {
		return true, ""
	}
	return false, ""
}

func isLoginSuccess(body []byte) bool {
	if value, err := jsonparser.GetString(body, "result"); err == nil {
		if value == "1" || strings.EqualFold(value, "success") || strings.EqualFold(value, "ok") {
			return true
		}
	}

	if value, err := jsonparser.GetInt(body, "result"); err == nil && value == 1 {
		return true
	}

	if value, err := jsonparser.GetBoolean(body, "result"); err == nil && value {
		return true
	}

	if value, err := jsonparser.GetBoolean(body, "success"); err == nil && value {
		return true
	}

	return false
}
