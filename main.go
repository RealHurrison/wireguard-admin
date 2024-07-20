package main

import (
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Model struct {
	ID        string `gorm:"type:uuid;primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Config struct {
	Subnet    string
	Interface string
}

type Admin struct {
	Model
	UserName string
	PassWord string
}

type Client struct {
	Model
	Name       string
	PrivateKey string
	PublicKey  string
	IP         string
	DNS        string
	Route      string
	Rules      []Rule
}

type Rule struct {
	Model
	ClientID string
	Protocol string
	DestIP   string
	DestPort string
	Action   string
}

type LoginRequest struct {
	UserName string
	PassWord string
}

var DB *gorm.DB

func initDatabase() {
	var err error
	DB, err = gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	DB.AutoMigrate(&Admin{})
}

func main() {
	initDatabase()
	DB.Create(&Admin{UserName: "admin", PassWord: "admin"})

	r := gin.Default()
	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var userLoginRequest LoginRequest
		if err := c.ShouldBindJSON(&userLoginRequest); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		var user Admin
		DB.Where("user_name = ?", userLoginRequest.UserName).First(&user)
		if user.PassWord == userLoginRequest.PassWord {
			c.JSON(200, gin.H{"message": "login success"})
		} else {
			c.JSON(401, gin.H{"message": "login failed"})
		}
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
