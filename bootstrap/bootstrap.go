package bootstrap

import (
	"wireguard-admin/background"
	"wireguard-admin/config"
	"wireguard-admin/db"
	"wireguard-admin/middleware"
	"wireguard-admin/router"
	"wireguard-admin/wireguard"
)

func Run() {
	config.Init()

	db.Init()

	wireguard.Init()

	background.Init()

	middleware.Init()

	router.Init()

	router.Run()
}
