package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
