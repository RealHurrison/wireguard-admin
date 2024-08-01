package background

import (
	"os"
	"os/signal"
	"syscall"

	"wireguard-admin/db"
	"wireguard-admin/wireguard"
)

func gracefulExit() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs

	println("Received signal: " + sig.String())
	println("Shutting down...")

	if !wireguard.DelWireguardInterface() {
		println("Failed to delete wireguard interface")
	}

	dbConnection, err := db.DB.DB()
	if err != nil {
		panic("failed to get database connection")
	}

	if err := dbConnection.Close(); err != nil {
		panic("failed to close database connection")
	}

	println("Server is down")

	os.Exit(0)
}
