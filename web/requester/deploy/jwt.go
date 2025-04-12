package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"net/http"
	"time"
)

var jwtSecret = "secret"

func JwtSecret() string {
	return jwtSecret
}

func SetJwtSecret(secret string) {
	jwtSecret = secret
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func generateJWT(userID int) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")
		if tokenString == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized, receive auth token in "+config.BotLink)
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized, receive auth token in "+config.BotLink)
		}
		return next(c)
	}
}

func init() {
	cfg := GetConfig()
	if len(cfg.TgBotToken) < 12 {
		panic("tg bot token too short")
	}

	SetJwtSecret(cfg.TgBotToken[:12])
}
