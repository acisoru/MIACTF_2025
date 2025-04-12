package main

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/andelf/go-curl"
	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type PingRequest struct {
	URL string `json:"url"`
}

func main() {
	//go startTgBot()

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(jwtMiddleware)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "redis",
		DB:       0,
	})

	e.POST("/ping", func(c echo.Context) error {
		ctx := c.Request().Context()
		req := new(PingRequest)
		if err := c.Bind(req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		}

		if req.URL == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "url field is required"})
		}

		if !allowedUrl(req.URL) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid url"})
		}

		cacheKey := "cache:" + req.URL
		cached, err := redisClient.Get(ctx, cacheKey).Result()
		if err == nil {
			return c.JSON(http.StatusOK, map[string]string{"result": cached})
		}

		easy := curl.EasyInit()
		defer easy.Cleanup()

		easy.Setopt(curl.OPT_VERBOSE, false)

		if err := easy.Setopt(curl.OPT_URL, req.URL); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch url"})
		}

		if err := easy.Setopt(curl.OPT_MAXFILESIZE, 1024*10); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch url"})
		}

		if err := easy.Setopt(curl.OPT_FOLLOWLOCATION, 0); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch url"})
		}
		if err := easy.Setopt(curl.OPT_TIMEOUT, 10); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch url"})
		}

		var responseBody string
		easy.Setopt(curl.OPT_WRITEFUNCTION, func(buf []byte, _ interface{}) bool {
			responseBody += string(buf)
			return true
		})

		if err := easy.Perform(); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch url"})
		}

		redisClient.Set(ctx, cacheKey, responseBody, 10*time.Second)
		return c.JSON(http.StatusOK, map[string]string{"result": responseBody})
	})

	if err := e.Start(":10010"); err != nil {
		e.Logger.Fatal(err)
	}
}

var (
	disallowedProtocols = []string{
		"DICT", "FILE", "FTP", "FTPS", "IMAP", "IMAPS", "LDAP", "LDAPS", "MQTT", "POP3",
		"POP3S", "RTMP", "RTMPS", "RTSP", "SCP", "SFTP", "SMB", "SMBS", "SMTP", "SMTPS", "TELNET", "TFTP", "WS", "WSS",
	}
)

func allowedUrl(u string) bool {
	uParsed, err := url.Parse(u)
	if err != nil {
		return false
	}

	if uParsed.Host == "" || uParsed.Scheme == "" {
		return false
	}

	if slices.Contains(disallowedProtocols, strings.ToUpper(uParsed.Scheme)) {
		return false
	}
	return true
}
