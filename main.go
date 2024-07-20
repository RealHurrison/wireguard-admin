package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Audit struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Config struct {
	Wireguard struct {
		Name   string
		Device string
		Subnet string
	}

	Server struct {
		Debug     bool
		Port      uint16
		Address   string
		SecretKey string
	}
}

type User struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key"`
	UserName string `gorm:"unique;not null"`
	PassWord string
}

type Client struct {
	Audit

	ID         string `gorm:"type:uuid;primary_key"`
	Name       string `gorm:"unique;not null"`
	PrivateKey string `gorm:"unique;not null"`
	PublicKey  string `gorm:"unique;not null"`
	IP         string `gorm:"unique;not null"`
	DNS        string
	Route      string
	Rules      []Rule
}

type Rule struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key"`
	ClientID string `gorm:"type:uuid;not null"`
	Protocol string
	DestIP   string
	DestPort string
	Action   string
}

type LoginRequest struct {
	UserName string
	PassWord string
}

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

var CONFIG *Config
var DB *gorm.DB

func initConfig() {
	CONFIG = &Config{}

	_, err := toml.DecodeFile("config.toml", CONFIG)

	if err != nil {
		panic("failed to load config: " + err.Error())
	}
}

func initDatabase() {
	var err error
	DB, err = gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	DB.AutoMigrate(&User{}, &Client{})
}

func requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
			c.Abort()
			return
		}
		tokenString = tokenString[7:]

		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(CONFIG.Server.SecretKey), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var user User
			if err := DB.First(&user, "id = ?", claims["id"].(string)).Error; err != nil {
				c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
				c.Abort()
				return
			}
			c.Set("user", user)
		} else {
			c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "Unauthorized", Data: nil})
			c.Abort()
			return
		}
		c.Next()
	}
}

func HashPassword(password string) string {
	sha2 := sha256.New()
	sha2.Write([]byte(password))
	bytes, err := bcrypt.GenerateFromPassword(sha2.Sum(nil), 12)
	if err != nil {
		panic("failed to hash password: " + err.Error())
	}

	return string(bytes)
}

func ComparePassword(hashedPassword, password string) bool {
	sha2 := sha256.New()
	sha2.Write([]byte(password))
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), sha2.Sum(nil))

	return err == nil
}

func main() {
	initConfig()
	initDatabase()
	DB.Create(&User{ID: uuid.New().String(), UserName: "admin", PassWord: HashPassword("admin")})

	if !CONFIG.Server.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	r.Use(gin.Recovery())

	if CONFIG.Server.Debug {
		r.Use(gin.Logger())
	}

	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, Response{Code: 0, Message: "pong", Data: nil})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var userLoginRequest LoginRequest
		if err := c.ShouldBindJSON(&userLoginRequest); err != nil {
			c.JSON(400, Response{Code: 400, Message: "Bad Request", Data: nil})
			return
		}

		var user User
		DB.Where("user_name = ?", userLoginRequest.UserName).First(&user)
		if !ComparePassword(user.PassWord, userLoginRequest.PassWord) {
			c.JSON(http.StatusUnauthorized, Response{Code: http.StatusUnauthorized, Message: "Invalid username or password", Data: nil})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":  user.ID,
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte(CONFIG.Server.SecretKey))
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Internal Server Error", Data: nil})
			return
		}

		c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"token": tokenString}})
	})

	authorizedRoute := r.Use(requireAuth())
	{
		authorizedRoute.GET("/api/authorized", requireAuth(), func(c *gin.Context) {
			user, _ := c.Get("user")
			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"user_name": user.(User).UserName}})
		})
	}

	println("Server is running on " + fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))

	r.Run(fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))
}
