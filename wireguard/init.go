package wireguard

import (
	"net"
	"os/exec"
	"strconv"
	"wireguard-admin/config"
	"wireguard-admin/db"
	"wireguard-admin/model"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddWireguardInterface() {
	cmd := exec.Command("ip", "link", "add", "dev", config.CONFIG.Wireguard.Name, "type", "wireguard")
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: Missing WireGuard kernel module")
	}

	cmd = exec.Command("ip", "-4", "address", "add", config.CONFIG.Wireguard.Network.String(), "dev", config.CONFIG.Wireguard.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: " + err.Error())
	}

	cmd = exec.Command("ip", "link", "set", "mtu", strconv.FormatUint(uint64(config.CONFIG.Wireguard.MTU), 10), "up", "dev", config.CONFIG.Wireguard.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		println(string(output))
		panic("failed to add wireguard interface: " + err.Error())
	}
}

func DelWireguardInterface() bool {
	cmd := exec.Command("ip", "link", "del", "dev", config.CONFIG.Wireguard.Name)
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

func SyncWireguardConfig() {
	wgc, err := wgctrl.New()
	if err != nil {
		panic("failed to create wireguard client: " + err.Error())
	}
	defer wgc.Close()

	var clients []model.Client
	db.DB.Find(&clients)

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
			PersistentKeepaliveInterval: &config.CONFIG.Wireguard.PersistentKeepalive,
			AllowedIPs:                  allowedIPs,
		}
	}

	wireguardConfig := wgtypes.Config{
		PrivateKey:   &config.CONFIG.Wireguard.PrivateKey.Key,
		ListenPort:   &config.CONFIG.Wireguard.Port,
		FirewallMark: &config.CONFIG.Wireguard.FirewallMark,
		ReplacePeers: true,
		Peers:        peers,
	}

	err = wgc.ConfigureDevice(config.CONFIG.Wireguard.Name, wireguardConfig)
	if err != nil {
		panic("failed to sync wireguard config: " + err.Error())
	}
}
