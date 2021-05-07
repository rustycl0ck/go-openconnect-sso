package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/mxschmitt/playwright-go"
	"github.com/rustycl0ck/go-openconnect-sso/config"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	var logger log.Logger

	var server = kingpin.Flag("server", "the OpenConnect VPN server address").Short('s').Required().String()
	var ocFile = kingpin.Flag("config", "the where OpenCOnnect config file will be saved").Short('c').Required().String()
	var logFormat = kingpin.Flag("log-format", "log format").Default("logfmt").Enum("json", "logfmt")
	var logLevel = kingpin.Flag("log-level", "log level [WARNING: 'debug' level will print openconnect login cookie to the console]").Default("info").Enum("info", "warn", "error", "debug", "none")
	kingpin.Parse()

	if *logFormat == "json" {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	} else {
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	}

	switch *logLevel {
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "warn":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
	case "debug":
		logger = level.NewFilter(logger, level.AllowDebug())
	case "none":
		logger = level.NewFilter(logger, level.AllowNone())
	}

	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	pw, err := playwright.Run()
	if err != nil {
		level.Error(logger).Log("msg", "could not launch playwright", "err", err)
	}
	browser, err := pw.Firefox.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(false),
	})
	if err != nil {
		level.Error(logger).Log("msg", "could not launch Firefox", "err", err)
	}
	context, err := browser.NewContext()
	if err != nil {
		level.Error(logger).Log("msg", "could not create context", "err", err)
	}
	page, err := context.NewPage()
	if err != nil {
		level.Error(logger).Log("msg", "could not create page", "err", err)
	}

	initResp, targetVPNServer := initializationStage(logger, *server)

	level.Info(logger).Log("msg", "waiting to detect successful authentication token cookie on the browser")
	page.Goto(initResp.LoginURL)

	var tokenCookie playwright.NetworkCookie

	for {
		foundCookie := false
		cookies, err := context.Cookies()
		if err != nil {
			level.Error(logger).Log("msg", "could not get cookies from browser context", "err", err)
		}

		for _, cookie := range cookies {
			if cookie.Name == initResp.TokenCookieName {
				tokenCookie = *cookie
				level.Info(logger).Log("msg", "received successful authentication token cookie from browser")
				foundCookie = true
				break
			}
		}
		if foundCookie {
			browser.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	finalResp := finalizationStage(logger, targetVPNServer, tokenCookie.Value, initResp.Opaque.Value)
	level.Info(logger).Log("msg", "received openconnect server fingerprint and connection cookie successfully")

	writeOCConfig(logger, finalResp.Cookie, finalResp.Fingerprint, targetVPNServer, *ocFile)
}

func initializationStage(logger log.Logger, url string) (config.InitializationResponse, string) {
	logger = log.With(logger, "stage", "initialization")

	// Get the final redirect-url from the initial server
	resp, err := http.Get(url)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get url", "url", url, "err", err)
		os.Exit(1)
	}
	targetVPNServer := resp.Request.URL.String()

	// Begin the authentication process: stage-1
	xmlPayload := fmt.Sprintf(`
    <config-auth client="vpn" type="init" aggregate-auth-version="2">
      <version who="vpn">4.7.00136</version>
      <device-id>linux-64</device-id>
      <group-select></group-select>
			<group-access>%s</group-access>
      <capabilities>
        <auth-method>single-sign-on-v2</auth-method>
      </capabilities>
    </config-auth>
	`, targetVPNServer)
	level.Debug(logger).Log("targetVPNServer", targetVPNServer)

	var result config.InitializationResponse
	body := makePostReq(logger, xmlPayload, targetVPNServer)

	level.Debug(logger).Log("msg", "received response from server", "body", string(body))

	if err := xml.Unmarshal(body, &result); err != nil {
		level.Error(logger).Log("msg", "failed to unmarshal the received response body to XML", "err", err, "body", string(body))
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "unmarshalled init response", "loginURL", result.LoginURL, "loginFinalURL", result.LoginFinalURL, "tokenCookieName", result.TokenCookieName, "opaque", result.Opaque.Value)
	return result, targetVPNServer
}

func finalizationStage(logger log.Logger, vpnServer string, token string, configHash string) config.FinalizationResponse {
	logger = log.With(logger, "stage", "finalization")

	xmlPayload := fmt.Sprintf(`
    <config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
      <version who="vpn">4.7.00136</version>
      <device-id>linux-64</device-id>
      <session-token/>
      <session-id/>
      <opaque is-for="sg">%s</opaque>
      <auth>
        <sso-token>%s</sso-token>
      </auth>
      </config-auth>
  `, configHash, token)

	var result config.FinalizationResponse
	body := makePostReq(logger, xmlPayload, vpnServer)

	level.Debug(logger).Log("msg", "received response from server", "body", string(body))

	if err := xml.Unmarshal(body, &result); err != nil {
		level.Error(logger).Log("msg", "failed to unmarshal the received response body to XML", "err", err, "body", string(body))
		os.Exit(1)
	}

	level.Debug(logger).Log("msg", "unmarshalled final response", "cookie", result.Cookie, "fingerprint", result.Fingerprint)
	return result
}

func makePostReq(logger log.Logger, xmlPayload, server string) []byte {

	req, err := http.NewRequest("POST", server, strings.NewReader(xmlPayload))
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create http request", "err", err)
		os.Exit(1)
	}
	headers := map[string]string{
		"User-Agent":          "AnyConnect Linux_64 4.7.00136",
		"Accept":              "*/*",
		"Accept-Encoding":     "identity",
		"X-Transcend-Version": "1",
		"X-Aggregate-Auth":    "1",
		"X-Support-HTTP-Auth": "true",
		"Content-Type":        "application/x-www-form-urlencoded",
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "failed to POST request to the server", "server", req.URL.String(), "err", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	level.Info(logger).Log("msg", "successfullly received response from server", "url", resp.Request.URL.String())
	level.Debug(logger).Log("msg", "received response", "body", string(body), "url", resp.Request.URL.String())

	return body
}

func writeOCConfig(logger log.Logger, cookie, fingerprint, server, ocFile string) {
	content := fmt.Sprintf("cookie=%s\nservercert=%s\n# host=%s\n", cookie, fingerprint, server)
	if err := os.WriteFile(ocFile, []byte(content), 0600); err != nil {
		level.Error(logger).Log("msg", "failed to write authentication details to file", "file", ocFile, "err", err)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "successfully written authentication details to file", "file", ocFile)
}
