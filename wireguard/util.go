package wireguard

func Init() {
	DelWireguardInterface()
	AddWireguardInterface()
	SyncWireguardConfig()
}
