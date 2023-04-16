package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
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
		tls_client.WithClientProfile(tls_client.Chrome_112),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}
	client, _   = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	account_map = make(map[string]map[string]string)
	HOST        = os.Getenv("HOST")
	PORT        = os.Getenv("PORT")
	http_proxy  = os.Getenv("http_proxy")

	access_token_str = os.Getenv("ACCESS_TOKEN")
	puid_str         = os.Getenv("PUID")
	cf_clearance_str = os.Getenv("CF_CLEARANCE")
	openai_email_str = os.Getenv("OPENAI_EMAIL")

	enable_puid_auto_refresh_str   = os.Getenv("ENABLE_PUID_AUTO_REFRESH")
	puid_auto_refresh_interval_str = os.Getenv("PUID_AUTO_REFRESH_INTERVAL")

	enable_puid_auto_refresh            = true
	puid_auto_refresh_interval_duration = 6 * time.Hour

	// admin_pass = os.Getenv("ADMIN_PASS")
)

func main() {
	if access_token_str == "" || cf_clearance_str == "" || openai_email_str == "" {
		println("Error: ACCESS_TOKEN, CF_CLEARANCE, OPENAI_EMAIL are not set correctly")
		os.Exit(1)
	}

	if http_proxy != "" {
		client.SetProxy(http_proxy)
		log.Println("Proxy set:" + http_proxy)
	}

	var access_tokens = strings.Split(access_token_str, ",")
	var cf_clearances = strings.Split(cf_clearance_str, ",")
	var openai_emails = strings.Split(openai_email_str, ",")

	if len(access_tokens) != len(cf_clearances) || len(access_tokens) != len(openai_emails) {
		println("Error: ACCESS_TOKEN, CF_CLEARANCE, OPENAI_EMAIL are not set correctly")
		os.Exit(1)
	}

	for i := 0; i < len(access_tokens); i++ {
		var access_token = access_tokens[i]
		if access_token != "" {
			account_map[access_token] = make(map[string]string)

			var cf_clearance = cf_clearances[i]
			var openai_email = openai_emails[i]

			account_map[access_token]["cf_clearance"] = cf_clearance
			account_map[access_token]["openai_email"] = openai_email
		}
	}

	if puid_str != "" {
		if enable_puid_auto_refresh_str != "" {
			enable_puid_auto_refresh = enable_puid_auto_refresh_str == "true"
		}

		if enable_puid_auto_refresh {

			var puids = strings.Split(puid_str, ",")

			if len(access_tokens) != len(puids) {
				println("Error: ACCESS_TOKEN and PUID are not set correctly")
				return
			}

			if puid_auto_refresh_interval_str != "" {
				if update_puid_interval, err := strconv.Atoi(puid_auto_refresh_interval_str); err == nil {
					puid_auto_refresh_interval_duration = time.Duration(update_puid_interval) * time.Hour
				} else {
					log.Fatalf("Error converting value to int: %v\n", err)
				}
			}

			// refresh puid every `update_puid_interval` hours
			go func() {
				for {
					account_map = make(map[string]map[string]string)
					// 使用 for 循环遍历字符串切片，将它们作为键值对添加到字典中
					for i := 0; i < len(access_tokens); i++ {
						var access_token = access_tokens[i]

						account_map[access_token]["puid"] = puids[i]
					}

					for access_token, value := range account_map {
						// Automatically refresh the puid cookie
						if access_token != "" {
							refreshPuid(access_token, value["puid"])
						}
					}
					time.Sleep(puid_auto_refresh_interval_duration)
				}
			}()
		}
	}

	if PORT == "" {
		PORT = "8080"
	}
	handler := gin.Default()
	handler.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	handler.Any("/api/*path", proxy)

	handler.POST("/admin/update", func(c *gin.Context) {
		// if c.Request.Header.Get("Authorization") != admin_pass {
		// 	c.JSON(401, gin.H{"message": "unauthorized"})
		// 	return
		// }

		type RequestData struct {
			AccessToken string            `json:"access_token"`
			AccessInfo  map[string]string `json:"access_info"`
		}
		var request RequestData
		c.BindJSON(&request)

		if request.AccessToken != "" {
			account_map[request.AccessToken] = request.AccessInfo
		}
		c.JSON(200, gin.H{"message": "updated"})
	})

	type RefreshPuidRequest struct {
		AccessToken string `json:"access_token"`
		Puid        string `json:"puid"`
	}

	type RefreshPuidResponse struct {
		Puid  string `json:"puid"`
		Error string `json:"error"`
	}

	handler.POST("/refresh_puid", func(c *gin.Context) {
		var req RefreshPuidRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// if access_token not in dict, add it
		_, ok := account_map[req.AccessToken]
		if !ok {
			account_map[req.AccessToken]["puid"] = req.Puid
		} else {
			req.Puid = refreshPuid(req.AccessToken, req.Puid)
		}

		if req.Puid == "" {
			c.JSON(http.StatusInternalServerError, &RefreshPuidResponse{Error: "refresh puid failed"})
		} else {
			account_map[req.AccessToken]["puid"] = req.Puid
			c.JSON(http.StatusOK, &RefreshPuidResponse{Puid: req.Puid})
		}
	})

	gin.SetMode(gin.ReleaseMode)
	log.Println("proxy starting at" + HOST + ":" + PORT + "... ")
	endless.ListenAndServe(HOST+":"+PORT, handler)
}

// !Obosolete
// Set authorization header
// Initial puid cookie
// Print response body
// Get cookies from response
// Find _puid cookie
func refreshPuid(access_token string, puid string) string {
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
		return ""
	}
	defer resp.Body.Close()
	log.Println("refreshPuid Got response: " + resp.Status)
	if resp.StatusCode != 200 {
		log.Println("Warning: " + resp.Status)

		body, _ := io.ReadAll(resp.Body)
		log.Println(string(body))

		// if puid is invalid, remove it from dict
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			delete(account_map[access_token], puid)
		}
		return ""
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

	return puid
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
	authorization := c.Request.Header.Get("Authorization")
	request.Header.Set("Authorization", authorization)

	request.Header.Set("sec-ch-ua", "\"Chromium\";v=\"112\", \"Brave\";v=\"112\", \"Not:A-Brand\";v=\"99\"")
	request.Header.Set("sec-ch-ua-mobile", "?0")
	request.Header.Set("sec-ch-ua-platform", "\"Linux\"")
	request.Header.Set("sec-fetch-dest", "empty")
	request.Header.Set("sec-fetch-mode", "cors")
	request.Header.Set("sec-fetch-site", "same-origin")
	request.Header.Set("sec-gpc", "1")
	request.Header.Set("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")

	// extract access token from authorization header
	access_token := strings.Split(authorization, " ")[1]

	// assert access_token in access_info_map keys
	access_info, ok := account_map[access_token]
	if !ok {
		// get puid from access_info_map randomly
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		access_tokens := make([]string, 0, len(account_map))
		for access_token := range account_map {
			access_tokens = append(access_tokens, access_token)
		}

		access_token := access_tokens[r.Intn(len(access_tokens))]
		access_info = account_map[access_token]
		log.Println("access_info from access_info_map randomly: " + fmt.Sprintf("%v", access_info["openai_email"]))
	} else {
		log.Println("access_info from access_info_map: " + fmt.Sprintf("%v", access_info["openai_email"]))
	}

	cf_clearance := access_info["cf_clearance"]
	if cf_clearance == "" {
		cf_clearance = c.Request.Header.Get("cf_clearance")
	}

	puid := access_info["puid"]
	if puid == "" {
		puid = c.Request.Header.Get("puid")
	}

	request.AddCookie(
		&http.Cookie{
			Name:  "cf_clearance",
			Value: cf_clearance,
		},
	)

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
