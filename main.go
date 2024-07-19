package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UserName string `json:"username"`
	PassWord string `json:"password"`
}

type UserLoginRequest struct {
	UserName string `json:"username"`
	PassWord string `json:"password"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{})
	db.Create(&User{UserName: "admin", PassWord: "admin"})

	r := gin.Default()
	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var userLoginRequest UserLoginRequest
		if err := c.ShouldBindJSON(&userLoginRequest); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		var user User
		db.Where("user_name = ?", userLoginRequest.UserName).First(&user)
		if user.PassWord == userLoginRequest.PassWord {
			c.JSON(200, gin.H{"message": "login success"})
		} else {
			c.JSON(401, gin.H{"message": "login failed"})
		}
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
