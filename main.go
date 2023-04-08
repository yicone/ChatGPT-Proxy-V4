package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
)

var (
	jar     = tls_client.NewCookieJar()
	options = []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(360),
		tls_client.WithClientProfile(tls_client.Chrome_110),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}
	client, _   = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	account_map = make(map[string]map[string]string)

	http_proxy = os.Getenv("http_proxy")
	auth_proxy = os.Getenv("auth_proxy")

	admin_pass = os.Getenv("ADMIN_PASS")
)

func main() {
	access_token_str := os.Getenv("ACCESS_TOKEN")
	puid_str := os.Getenv("PUID")
	cf_clearance_str := os.Getenv("CF_CLEARANCE")
	openai_email_str := os.Getenv("OPENAI_EMAIL")
	openai_pass_str := os.Getenv("OPENAI_PASS")

	if access_token_str == "" && cf_clearance_str == "" && openai_email_str == "" && openai_pass_str == "" {
		println("Error: Authentication information not found.")
		return
	}

	var access_tokens = strings.Split(access_token_str, ",")
	var cf_clearances = strings.Split(cf_clearance_str, ",")
	var openai_emails = strings.Split(openai_email_str, ",")
	var openai_passs = strings.Split(openai_pass_str, ",")

	for i := 0; i < len(access_tokens); i++ {
		var access_token = access_tokens[i]
		account_map[access_token] = make(map[string]string)

		var cf_clearance = cf_clearances[i]
		var openai_email = openai_emails[i]
		var openai_pass = openai_passs[i]

		account_map[access_token]["cf_clearance"] = cf_clearance
		account_map[access_token]["openai_email"] = openai_email
		account_map[access_token]["openai_pass"] = openai_pass
	}

	if puid_str != "" {
		refresh_puid_interval_str := os.Getenv("REFRESH_PUID_INTERVAL")
		if refresh_puid_interval_str == "" {
			refresh_puid_interval_str = "6"
		}

		update_puid_interval, err := strconv.Atoi(refresh_puid_interval_str)
		if err != nil {
			fmt.Printf("Error converting value to int: %v\n", err)
		}

		update_puid_interval_duration := time.Duration(update_puid_interval) * time.Hour

		// refresh puid every `update_puid_interval` hours
		go func() {
			for {
				// build a dict that access token as key and puid as value
				var puids = strings.Split(puid_str, ",")

				if len(access_tokens) != len(puids) {
					println("Error: ACCESS_TOKEN and PUID are not set correctly")
					return
				}

				account_map = make(map[string]map[string]string)
				// 使用 for 循环遍历字符串切片，将它们作为键值对添加到字典中
				for i := 0; i < len(access_tokens); i++ {
					var access_token = access_tokens[i]

					account_map[access_token]["puid"] = puids[i]
				}

				for access_token, value := range account_map {
					if http_proxy != "" {
						client.SetProxy(http_proxy)
						println("Proxy set:" + http_proxy)
					}
					// Automatically refresh the puid cookie
					if access_token != "" {
						refreshPuid(access_token, value["puid"])
					}
				}
				time.Sleep(update_puid_interval_duration)
			}
		}()
	}

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}
	handler := gin.Default()
	handler.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	handler.Any("/api/*path", proxy)

	handler.POST("/admin/update", func(c *gin.Context) {
		if c.Request.Header.Get("Authorization") != admin_pass {
			c.JSON(401, gin.H{"message": "unauthorized"})
			return
		}
		type Update struct {
			Value string `json:"value"`
			Field string `json:"field"`
		}
		var update Update
		c.BindJSON(&update)

		// if update.Field == "cf_clearance" {
		// 	cf_clearance = update.Value
		// 	// export environment variable
		// 	// os.Setenv("CF_CLEARANCE", cf_clearance)
		// } else if update.Field == "access_token" {
		// 	access_token = update.Value
		// 	// os.Setenv("ACCESS_TOKEN", access_token)
		// } else
		if update.Field == "http_proxy" {
			http_proxy = update.Value
			client.SetProxy(http_proxy)
			// } else if update.Field == "openai_email" {
			// 	openai_email = update.Value
			// 	// os.Setenv("OPENAI_EMAIL", openai_email)
			// } else if update.Field == "openai_pass" {
			// 	openai_pass = update.Value
			// 	// os.Setenv("OPENAI_PASS", openai_pass)
		} else if update.Field == "admin_pass" {
			admin_pass = update.Value
			// os.Setenv("ADMIN_PASS", admin_pass)
		} else if update.Field == "auth_proxy" {
			auth_proxy = update.Value
			// os.Setenv("auth_proxy", auth_proxy)
		} else {
			c.JSON(400, gin.H{"message": "field not found"})
			return
		}
		c.JSON(200, gin.H{"message": "updated"})
	})
	gin.SetMode(gin.ReleaseMode)
	endless.ListenAndServe(os.Getenv("HOST")+":"+PORT, handler)
}

// Set authorization header
// Initial puid cookie
// Print response body
// Get cookies from response
// Find _puid cookie
func refreshPuid(access_token string, puid string) {
	url := "https://chat.openai.com/backend-api/models"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Host", "chat.openai.com")
	req.Header.Set("origin", "https://chat.openai.com/chat")
	req.Header.Set("referer", "https://chat.openai.com/chat")
	req.Header.Set("sec-ch-ua", `Chromium";v="110", "Not A(Brand";v="24", "Brave";v="110`)
	req.Header.Set("sec-ch-ua-platform", "Linux")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

	req.Header.Set("Authorization", "Bearer "+access_token)

	req.AddCookie(
		&http.Cookie{
			Name:  "_puid",
			Value: puid,
		},
	)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	println("refreshPuid Got response: " + resp.Status)
	if resp.StatusCode != 200 {
		println("Warning: " + resp.Status)

		body, _ := io.ReadAll(resp.Body)
		println(string(body))
		return
	}

	cookies := resp.Cookies()

	for _, cookie := range cookies {
		if cookie.Name == "_puid" {
			puid = cookie.Value
			println("puid: " + puid)
			account_map[access_token]["puid"] = puid
			break
		}
	}
}

func proxy(c *gin.Context) {

	var url string
	var err error
	var request_method string
	var request *http.Request
	var response *http.Response

	if c.Request.URL.RawQuery != "" {
		url = "https://chat.openai.com/backend-api" + c.Param("path") + "?" + c.Request.URL.RawQuery
	} else {
		url = "https://chat.openai.com/backend-api" + c.Param("path")
	}
	request_method = c.Request.Method

	request, err = http.NewRequest(request_method, url, c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	request.Header.Set("Host", "chat.openai.com")
	request.Header.Set("Origin", "https://chat.openai.com/chat")
	request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Keep-Alive", "timeout=360")
	request.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
	authorization := c.Request.Header.Get("Authorization")
	request.Header.Set("Authorization", authorization)

	// extract access token from authorization header
	access_token := strings.Split(authorization, " ")[1]

	cf_clearance := account_map[access_token]["puid"]
	if cf_clearance == "" {
		cf_clearance = c.Request.Header.Get("cf_clearance")
	}
	request.AddCookie(
		&http.Cookie{
			Name:  "cf_clearance",
			Value: cf_clearance,
		},
	)

	// get puid from access_token_puid_dict
	puid := account_map[access_token]["puid"]
	if puid == "" {
		puid = c.Request.Header.Get("puid")
	}

	if puid != "" {
		request.AddCookie(
			&http.Cookie{
				Name:  "_puid",
				Value: puid,
			},
		)
	}

	response, err = client.Do(request)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer response.Body.Close()
	c.Header("Content-Type", response.Header.Get("Content-Type"))
	// Get status code
	c.Status(response.StatusCode)
	c.Stream(func(w io.Writer) bool {
		// Write data to client
		io.Copy(w, response.Body)
		return false
	})

}
