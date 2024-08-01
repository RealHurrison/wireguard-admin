package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Network struct {
	IP    net.IP
	IPNet net.IPNet
}

type Key struct {
	wgtypes.Key
}

type Config struct {
	Wireguard struct {
		Name                string        `toml:"name"`
		Device              string        `toml:"device"`
		Network             Network       `toml:"network"`
		Port                int           `toml:"port"`
		MTU                 uint16        `toml:"mtu"`
		FirewallMark        int           `toml:"firewall_mark"`
		PersistentKeepalive time.Duration `toml:"persistent_keepalive"`
		PrivateKey          Key           `toml:"private_key"`
		PublicKey           Key           `toml:"public_key"`
	}

	Server struct {
		Debug     bool   `toml:"debug"`
		Port      uint16 `toml:"port"`
		Address   string `toml:"address"`
		SecretKey string `toml:"secret_key"`
	}
}

type Audit struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key"`
	UserName string `gorm:"unique;not null;default:null"`
	PassWord string `gorm:"not null;default:null"`
}

type Client struct {
	Audit

	ID           string `gorm:"type:uuid;primary_key" json:"id"`
	Name         string `gorm:"unique;not null;default:null" json:"name"`
	PrivateKey   string `gorm:"unique;not null;default:null" json:"private_key"`
	PublicKey    string `gorm:"unique;not null;default:null" json:"public_key"`
	PresharedKey string `gorm:"unique;not null;default:null" json:"preshared_key"`
	IP           string `gorm:"unique;not null;default:null" json:"ip"`
	DNS          string `json:"dns"`
	Route        string `json:"route"`
	Rules        []Rule `gorm:"foreignKey:ClientID" json:"-"`
}

type Rule struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key" json:"id"`
	ClientID string `gorm:"type:uuid;not null;index:idx_unique,unique" json:"-"`
	Protocol string `json:"protocol"`
	DestIP   string `json:"dest_ip"`
	DestPort string `json:"dest_port"`
	Action   string `json:"action"`
	Priority int    `gorm:"not null;index:idx_unique,unique" json:"priority"`
}

type LoginRequest struct {
	UserName string `json:"username" binding:"required"`
	PassWord string `json:"password" binding:"required"`
}

type CreateClientRequest struct {
	Name string `json:"name" binding:"required"`
	IP   string `json:"ip" binding:"required"`
	DNS  string `json:"dns"`
}

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

var CONFIG *Config
var DB *gorm.DB

func (network *Network) UnmarshalText(text []byte) error {
	ip, ipnet, err := net.ParseCIDR(string(text))
	if err == nil {
		network.IP = ip
		network.IPNet = *ipnet
	}

	return err
}

func (key *Key) UnmarshalText(text []byte) error {
	bytes, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	if len(bytes) != wgtypes.KeyLen {
		return fmt.Errorf("invalid key length: %d", len(text))
	}

	copy(key.Key[:], bytes)
	return nil
}

func (network *Network) String() string {
	ipnet := net.IPNet{}
	ipnet.IP = network.IP
	ipnet.Mask = network.IPNet.Mask
	return ipnet.String()
}

func initConfig() {
	CONFIG = &Config{}

	_, err := toml.DecodeFile("config.toml", CONFIG)

	println(CONFIG.Server.SecretKey)

	if err != nil {
		panic("failed to load config: " + err.Error())
	}
}

func initDatabase() {
	_, err := os.Stat("data")
	if os.IsNotExist(err) {
		if os.Mkdir("data", 0600) != nil {
			panic("failed to create data directory")
		}
	}

	DB, err = gorm.Open(sqlite.Open("data/data.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	DB.AutoMigrate(&User{}, &Client{}, &Rule{})
}

func addWireguardInterface() {
	cmd := exec.Command("ip", "link", "add", "dev", CONFIG.Wireguard.Name, "type", "wireguard")
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: Missing WireGuard kernel module")
	}

	cmd = exec.Command("ip", "-4", "address", "add", CONFIG.Wireguard.Network.String(), "dev", CONFIG.Wireguard.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: " + err.Error())
	}

	cmd = exec.Command("ip", "link", "set", "mtu", strconv.FormatUint(uint64(CONFIG.Wireguard.MTU), 10), "up", "dev", CONFIG.Wireguard.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: " + err.Error())
	}
}

func delWireguardInterface() bool {
	cmd := exec.Command("ip", "link", "del", "dev", CONFIG.Wireguard.Name)
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

func syncWireguardConfig() {
	// config := GenerateWireguardConfig()
	// cmd := exec.Command("wg", "setconf", CONFIG.Wireguard.Name, "/dev/stdin")
	// cmd.Stdin = bytes.NewReader([]byte(config))

	// if output, err := cmd.CombinedOutput(); err != nil {
	// 	println(string(output))
	// 	panic("failed to sync wireguard config: " + err.Error())
	// }
	wgc, err := wgctrl.New()
	if err != nil {
		panic("failed to create wireguard client: " + err.Error())
	}
	defer wgc.Close()

	var clients []Client
	DB.Find(&clients)

	peers := make([]wgtypes.PeerConfig, len(clients))
	for i, client := range clients {
		publicKey, err := wgtypes.ParseKey(client.PublicKey)
		if err != nil {
			panic("failed to parse public key: " + err.Error())
		}

		preSharedKey, err := wgtypes.ParseKey(client.PresharedKey)
		if err != nil {
			panic("failed to parse preshared key: " + err.Error())
		}

		allowedIPs := []net.IPNet{
			{
				IP:   net.ParseIP(client.IP),
				Mask: net.CIDRMask(32, 32),
			},
		}

		peers[i] = wgtypes.PeerConfig{
			PublicKey:                   publicKey,
			PresharedKey:                &preSharedKey,
			Remove:                      false,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &CONFIG.Wireguard.PersistentKeepalive,
			AllowedIPs:                  allowedIPs,
		}
	}

	config := wgtypes.Config{
		PrivateKey:   &CONFIG.Wireguard.PrivateKey.Key,
		ListenPort:   &CONFIG.Wireguard.Port,
		FirewallMark: &CONFIG.Wireguard.FirewallMark,
		ReplacePeers: true,
		Peers:        peers,
	}

	err = wgc.ConfigureDevice(CONFIG.Wireguard.Name, config)
	if err != nil {
		panic("failed to sync wireguard config: " + err.Error())
	}
}

func initWireguard() {
	delWireguardInterface()
	addWireguardInterface()
	syncWireguardConfig()

	println("Wireguard is running")
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

func MustObtainLimitAndOffset(c *gin.Context, minLimit int, maxLimit int) (int, int) {
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
	DB.Model(&Client{}).Where("id = ?", id).Count(&count)
	return count > 0
}

func CheckClientExistByName(name string) bool {
	var count int64
	DB.Model(&Client{}).Where("name = ?", name).Count(&count)
	return count > 0
}

func CheckClientExistByIP(ip string) bool {
	var count int64
	DB.Model(&Client{}).Where("ip = ?", ip).Count(&count)
	return count > 0
}

// func GenerateWireguardConfig() string {
// 	config := ini.Empty(ini.LoadOptions{
// 		AllowNonUniqueSections: true,
// 	})
// 	interfaceSection, _ := config.NewSection("Interface")
// 	interfaceSection.NewKey("PrivateKey", CONFIG.Wireguard.PrivateKey)
// 	interfaceSection.NewKey("ListenPort", fmt.Sprintf("%d", CONFIG.Wireguard.Port))

// 	var clients []Client
// 	DB.Find(&clients)
// 	for _, client := range clients {
// 		peerSection, _ := config.NewSection("Peer")
// 		peerSection.NewKey("PublicKey", client.PublicKey)
// 		peerSection.NewKey("AllowedIPs", fmt.Sprintf("%s/32", client.IP))
// 	}

// 	writer := bytes.NewBuffer(nil)
// 	config.WriteTo(writer)
// 	return writer.String()
// }

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

func GracefulExit() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs

	println("Received signal: " + sig.String())
	println("Shutting down...")

	if !delWireguardInterface() {
		println("Failed to delete wireguard interface")
	}

	db, err := DB.DB()
	if err != nil {
		panic("failed to get database connection")
	}

	if err := db.Close(); err != nil {
		panic("failed to close database connection")
	}

	println("Server is down")

	os.Exit(0)
}

func main() {
	initConfig()
	initDatabase()
	initWireguard()

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

	authorizedRoute := r.Group("/", requireAuth())
	{
		authorizedRoute.GET("/api/authorized", func(c *gin.Context) {
			user, _ := c.Get("user")
			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"username": user.(User).UserName}})
		})

		authorizedRoute.POST("/api/wireguard/sync", func(c *gin.Context) {
			syncWireguardConfig()
			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: nil})
		})

		authorizedRoute.POST("/api/client", func(c *gin.Context) {
			var request CreateClientRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Bad Request", Data: nil})
				return
			}

			if CheckClientExistByName(request.Name) {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Duplicate client name", Data: nil})
				return
			}

			ip, err := ValidateClientIP(request.IP)
			if err != nil {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: err.Error(), Data: nil})
				return
			}

			if request.DNS != "" {
				dns := net.ParseIP(request.DNS)
				if dns == nil {
					c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Invalid DNS address", Data: nil})
					return
				}
				request.DNS = dns.String()
			}

			preSharedKey, err := wgtypes.GenerateKey()
			if err != nil {
				c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Failed to generate preshared key", Data: nil})
				return
			}
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Failed to generate private key", Data: nil})
				return
			}

			client := Client{
				ID:           uuid.New().String(),
				Name:         request.Name,
				IP:           ip.String(),
				DNS:          request.DNS,
				PrivateKey:   privateKey.String(),
				PublicKey:    privateKey.PublicKey().String(),
				PresharedKey: preSharedKey.String(),
			}

			if err := DB.Create(&client).Error; err != nil {
				c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Failed to create client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: gin.H{"id": client.ID}})

		})

		authorizedRoute.GET("/api/client", func(c *gin.Context) {
			limit, offset := MustObtainLimitAndOffset(c, 10, 50)
			var clients []Client
			DB.Limit(limit).Offset(offset).Find(&clients)
			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: clients})
		})

		authorizedRoute.GET("/api/client/:id", func(c *gin.Context) {
			var client Client
			if err := DB.First(&client, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: client})
		})

		authorizedRoute.PUT("/api/client/:id", func(c *gin.Context) {
			var client Client
			if err := DB.Omit("rules").First(&client, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			var request CreateClientRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Bad Request", Data: nil})
				return
			}

			if request.Name != client.Name && CheckClientExistByName(request.Name) {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Duplicate client name", Data: nil})
				return
			}

			if request.IP != client.IP {
				ip, err := ValidateClientIP(request.IP)
				if err != nil {
					c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: err.Error(), Data: nil})
					return
				}
				client.IP = ip.String()
			}

			if request.DNS != client.DNS && request.DNS != "" {
				dns := net.ParseIP(request.DNS)
				if dns == nil {
					c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Invalid DNS address", Data: nil})
					return
				}
				request.DNS = dns.String()
			}

			client.Name = request.Name
			client.IP = request.IP
			client.DNS = request.DNS

			if err := DB.Save(&client).Error; err != nil {
				c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Failed to update client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: nil})
		})

		authorizedRoute.DELETE("/api/client/:id", func(c *gin.Context) {
			if !CheckClientExistByID(c.Param("id")) {
				c.JSON(http.StatusBadRequest, Response{Code: http.StatusBadRequest, Message: "Invalid client id", Data: nil})
				return
			}

			if err := DB.Delete(&Client{}, "id = ?", c.Param("id")).Error; err != nil {
				c.JSON(http.StatusInternalServerError, Response{Code: http.StatusInternalServerError, Message: "Failed to delete client", Data: nil})
				return
			}

			c.JSON(http.StatusOK, Response{Code: http.StatusOK, Message: "OK", Data: nil})
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

	go GracefulExit()

	println("Server is running on " + fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))

	r.Run(fmt.Sprintf("%s:%d", CONFIG.Server.Address, CONFIG.Server.Port))
}
