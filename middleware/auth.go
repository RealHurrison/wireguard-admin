package middleware

import (
	"net/http"
	"wireguard-admin/config"
	"wireguard-admin/db"
	"wireguard-admin/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, model.Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
			c.Abort()
			return
		}
		tokenString = tokenString[7:]

		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.CONFIG.Server.SecretKey), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var user model.User
			if err := db.DB.First(&user, "id = ?", claims["id"].(string)).Error; err != nil {
				c.JSON(http.StatusUnauthorized, model.Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
				c.Abort()
				return
			}
			c.Set("user", user)
		} else {
			c.JSON(http.StatusUnauthorized, model.Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
			c.Abort()
			return
		}
		c.Next()
	}
}
