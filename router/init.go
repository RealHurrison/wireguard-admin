package router

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"wireguard-admin/config"
	"wireguard-admin/db"
	"wireguard-admin/middleware"
	"wireguard-admin/model"
	"wireguard-admin/util"
	"wireguard-admin/wireguard"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gorm.io/gorm"
)

var (
	CONFIG *config.Config
	DB     *gorm.DB
	r      *gin.Engine
)

func MustObtainLimitAndOffset(c *gin.Context, minLimit, maxLimit int) (int, int) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit <= 0 {
		limit = minLimit
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 {
		offset = 0
	}

	return limit, offset
}

func CheckClientExistByID(id string) bool {
	var count int64
	DB.Model(&model.Client{}).Where("id = ?", id).Count(&count)
	return count > 0
}

func CheckClientExistByName(name string) bool {
	var count int64
	DB.Model(&model.Client{}).Where("name = ?", name).Count(&count)
	return count > 0
}

func CheckClientExistByIP(ip string) bool {
	var count int64
	DB.Model(&model.Client{}).Where("ip = ?", ip).Count(&count)
	return count > 0
}

func ValidateClientIP(ipString string) (net.IP, error) {
	ip := net.ParseIP(ipString)

	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	if !CONFIG.Wireguard.Network.IPNet.Contains(ip) {
		return nil, fmt.Errorf("%s not in subnet %s", ipString, CONFIG.Wireguard.Network.IPNet.String())
	}

	if CONFIG.Wireguard.Network.IP.Equal(ip) {
		return nil, fmt.Errorf("%s is gateway", ipString)
	}

	if CheckClientExistByIP(ip.String()) {
		return nil, fmt.Errorf("%s already exists", ipString)
	}

	return ip, nil
}

func Init() {
	CONFIG = config.CONFIG
	DB = db.DB

	if !CONFIG.Server.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r = gin.New()

	r.Use(gin.Recovery())

	if CONFIG.Server.Debug {
		r.Use(gin.Logger())
	}

	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, model.Response{Code: 0, Message: "pong", Data: nil})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var userLoginRequest model.LoginRequest
		if err := c.ShouldBindJSON(&userLoginRequest); err != nil {
			c.JSON(400, model.Response{Code: 400, Message: "Bad Request", Data: nil})
			return
		}

		var user model.User
		DB.Where("user_name = ?", userLoginRequest.UserName).First(&user)
		if !util.ComparePassword(user.PassWord, userLoginRequest.PassWord) {
			c.JSON(http.StatusUnauthorized, model.Response{Code: http.StatusUnauthorized, Message: "Invalid username or password", Data: nil})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":  user.ID,
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte(CONFIG.Server.SecretKey))
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Internal Server Error", Data: nil})
			return
		}

		c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"token": tokenString}})
	})

	authorizedRoute := r.Group("/", middleware.RequireAuth())
	{
		authorizedRoute.GET("/api/authorized", func(c *gin.Context) {
			user, _ := c.Get("user")
			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"username": user.(model.User).UserName}})
		})

		authorizedRoute.POST("/api/wireguard/sync", func(c *gin.Context) {
			wireguard.SyncWireguardConfig()
			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: nil})
		})

		authorizedRoute.POST("/api/client", func(c *gin.Context) {
			var request model.CreateClientRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Bad Request", Data: nil})
				return
			}

			if CheckClientExistByName(request.Name) {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Duplicate client name", Data: nil})
				return
			}

			ip, err := ValidateClientIP(request.IP)
			if err != nil {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: err.Error(), Data: nil})
				return
			}

			if request.DNS != "" {
				dns := net.ParseIP(request.DNS)
				if dns == nil {
					c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Invalid DNS address", Data: nil})
					return
				}
				request.DNS = dns.String()
			}

			preSharedKey, err := wgtypes.GenerateKey()
			if err != nil {
				c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Failed to generate preshared key", Data: nil})
				return
			}
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Failed to generate private key", Data: nil})
				return
			}

			client := model.Client{
				ID:           uuid.New().String(),
				Name:         request.Name,
				IP:           ip.String(),
				DNS:          request.DNS,
				PrivateKey:   privateKey.String(),
				PublicKey:    privateKey.PublicKey().String(),
				PresharedKey: preSharedKey.String(),
			}

			if err := DB.Create(&client).Error; err != nil {
				c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Failed to create client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"id": client.ID}})
		})

		authorizedRoute.GET("/api/client", func(c *gin.Context) {
			limit, offset := MustObtainLimitAndOffset(c, 10, 50)
			var clients []model.Client
			DB.Limit(limit).Offset(offset).Find(&clients)
			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: clients})
		})

		authorizedRoute.GET("/api/client/:id", func(c *gin.Context) {
			var client model.Client
			if err := DB.First(&client, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: client})
		})

		authorizedRoute.PUT("/api/client/:id", func(c *gin.Context) {
			var client model.Client
			if err := DB.Omit("rules").First(&client, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			var request model.CreateClientRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Bad Request", Data: nil})
				return
			}

			if request.Name != client.Name && CheckClientExistByName(request.Name) {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Duplicate client name", Data: nil})
				return
			}

			if request.IP != client.IP {
				ip, err := ValidateClientIP(request.IP)
				if err != nil {
					c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: err.Error(), Data: nil})
					return
				}
				client.IP = ip.String()
			}

			if request.DNS != client.DNS && request.DNS != "" {
				dns := net.ParseIP(request.DNS)
				if dns == nil {
					c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Invalid DNS address", Data: nil})
					return
				}
				request.DNS = dns.String()
			}

			client.Name = request.Name
			client.IP = request.IP
			client.DNS = request.DNS

			if err := DB.Save(&client).Error; err != nil {
				c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Failed to update client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: nil})
		})

		authorizedRoute.DELETE("/api/client/:id", func(c *gin.Context) {
			if !CheckClientExistByID(c.Param("id")) {
				c.JSON(http.StatusBadRequest, model.Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			if err := DB.Delete(&model.Client{}, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusInternalServerError, model.Response{Code: http.StatusInternalServerError, Message: "Failed to delete client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, model.Response{Code: http.StatusOK, Message: "OK", Data: nil})
		})

		authorizedRoute.POST("/api/client/:id/rule", func(c *gin.Context) {
		})

		authorizedRoute.GET("/api/client/:id/rule", func(c *gin.Context) {
		})

		authorizedRoute.GET("/api/client/:id/rule/:rule_id", func(c *gin.Context) {
		})

		authorizedRoute.PUT("/api/client/:id/rule/:rule_id", func(c *gin.Context) {
		})
	}

	r.NoRoute(gin.WrapH(http.FileServer(gin.Dir("public", false))))
}

func Run() {
	println("Server is running on " + fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))

	err := r.Run(fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))
	if err != nil {
		panic("failed to start server: " + err.Error())
	}
}
